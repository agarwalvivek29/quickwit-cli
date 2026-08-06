package audit

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// PGXSink writes audit records to Postgres via a pgxpool.
type PGXSink struct {
	pool *pgxpool.Pool
}

// NewPGXSink opens a pooled connection to dsn and returns a Sink.
func NewPGXSink(ctx context.Context, dsn string) (*PGXSink, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open audit pool: %w", err)
	}
	return &PGXSink{pool: pool}, nil
}

// Close releases the pool.
func (s *PGXSink) Close() { s.pool.Close() }

// Ping checks connectivity.
func (s *PGXSink) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// EnsureSchema applies the embedded DDL (idempotent).
func (s *PGXSink) EnsureSchema(ctx context.Context) error {
	// No args -> pgx uses the simple protocol, which allows the multi-statement
	// script.
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

// EnsurePartitions creates the current and next month partitions and drops the
// partition that has aged past retentionMonths. Run at startup and monthly.
func (s *PGXSink) EnsurePartitions(ctx context.Context, now time.Time, retentionMonths int) error {
	start := monthStart(now)
	for _, mo := range []time.Time{start, start.AddDate(0, 1, 0)} {
		name := partitionName(mo)
		from := mo.Format("2006-01-02")
		to := mo.AddDate(0, 1, 0).Format("2006-01-02")
		q := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF qw_audit FOR VALUES FROM ('%s') TO ('%s')`,
			name, from, to,
		)
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("create partition %s: %w", name, err)
		}
	}
	if retentionMonths > 0 {
		old := partitionName(start.AddDate(0, -retentionMonths, 0))
		if _, err := s.pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, old)); err != nil {
			return fmt.Errorf("drop old partition %s: %w", old, err)
		}
	}
	return nil
}

// InsertBatch inserts recs in a single pipelined batch.
func (s *PGXSink) InsertBatch(ctx context.Context, recs []Record) error {
	const q = `INSERT INTO qw_audit
		(ts, principal_sub, principal_email, client_ip, user_agent, cli_version,
		 method, path, index, query_body, status_code, latency_ms, bytes_out)
		VALUES ($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`

	batch := &pgx.Batch{}
	for _, r := range recs {
		batch.Queue(q,
			r.Ts,
			nilStr(r.PrincipalSub), nilStr(r.PrincipalEmail),
			nilStr(r.ClientIP), nilStr(r.UserAgent), nilStr(r.CLIVersion),
			nilStr(r.Method), nilStr(r.Path), nilStr(r.Index),
			nilBytes(r.QueryBody),
			r.StatusCode, r.LatencyMS, r.BytesOut,
		)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()
	for range recs {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func nilStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilBytes(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}

func monthStart(t time.Time) time.Time {
	y, m, _ := t.UTC().Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}

func partitionName(t time.Time) string {
	return fmt.Sprintf("qw_audit_%04d%02d", t.Year(), int(t.Month()))
}
