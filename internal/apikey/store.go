// Package apikey is qwproxy's long-lived API-key store. An OIDC-authenticated
// user mints a key; thereafter the proxy authorizes the presented key by a local
// SHA-256 hash lookup against Postgres — no OIDC round trip. Only the hash is
// stored, never the raw key. A key authorizes iff it exists, is unexpired, and
// has not been revoked.
//
// The store mirrors internal/audit: a bounded pgxpool and an embedded schema.sql
// applied idempotently via EnsureSchema at startup, so a deploy never needs a
// manual migration step.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

//go:embed schema.sql
var schemaSQL string

// KeyPrefix marks every minted key. The proxy uses it as a cheap pre-check
// before hashing, and it makes a leaked key recognizable in logs/config.
const KeyPrefix = "qw_pat_"

// prefixDisplayLen is how many leading characters of a key we store in plaintext
// for display in `qw apikey list` (KeyPrefix + a few random chars — enough to
// tell keys apart, not enough to be useful if leaked).
const prefixDisplayLen = len(KeyPrefix) + 6

// keyRandomBytes is the entropy per key (256 bits), hex-encoded into the key.
const keyRandomBytes = 32

// ErrInvalidKey is returned by Authenticate for any key that is malformed,
// unknown, expired, or revoked. It is deliberately undifferentiated so the proxy
// cannot leak which of those a given key is.
var ErrInvalidKey = errors.New("invalid api key")

// Created is the result of minting a key. APIKey is the raw secret and is
// returned exactly once — it is never recoverable afterwards.
type Created struct {
	ID        string
	APIKey    string
	ExpiresAt time.Time
}

// Info is a key's metadata for listing (never includes the hash or raw key).
type Info struct {
	ID          string
	Prefix      string
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	LastUsedAt  *time.Time
}

// Store persists and validates API keys in Postgres.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewPGXStore opens a small, bounded pool against dsn. The store issues only
// point lookups and single-row writes, so it needs very few connections; the cap
// keeps qwproxy (possibly several replicas) from exhausting Postgres.
func NewPGXStore(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse api-key dsn: %w", err)
	}
	if cfg.MaxConns < 2 {
		cfg.MaxConns = 2
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open api-key pool: %w", err)
	}
	return &Store{pool: pool, now: time.Now}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// EnsureSchema applies the embedded DDL (idempotent). Called at startup so a
// deploy self-migrates with no manual step.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply api-key schema: %w", err)
	}
	return nil
}

// Create mints a key for the given principal, valid for ttl. It returns the raw
// key (shown once) alongside its id and expiry.
func (s *Store) Create(ctx context.Context, sub, email, description string, ttl time.Duration) (*Created, error) {
	if sub == "" {
		return nil, errors.New("cannot mint an api key without a principal subject")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	raw, err := generateKey()
	if err != nil {
		return nil, err
	}
	hash := hashKey(raw)
	expiresAt := s.now().UTC().Add(ttl)

	var id string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO qw_api_keys (key_hash, prefix, principal_sub, principal_email, description, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id::text`,
		hash, raw[:prefixDisplayLen], sub, nilStr(email), nilStr(description), expiresAt,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert api key: %w", err)
	}
	return &Created{ID: id, APIKey: raw, ExpiresAt: expiresAt}, nil
}

// Authenticate validates a raw key and returns the creator's identity claims for
// the audit trail. It returns ErrInvalidKey for anything not currently valid.
// A successful lookup asynchronously stamps last_used_at (best effort).
func (s *Store) Authenticate(ctx context.Context, raw string) (*oidc.Claims, error) {
	if !strings.HasPrefix(raw, KeyPrefix) {
		return nil, ErrInvalidKey
	}
	hash := hashKey(raw)

	var (
		sub, email string
		expiresAt  time.Time
		revokedAt  *time.Time
	)
	err := s.pool.QueryRow(ctx,
		`SELECT principal_sub, COALESCE(principal_email,''), expires_at, revoked_at
		 FROM qw_api_keys WHERE key_hash = $1`, hash,
	).Scan(&sub, &email, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidKey
	}
	if err != nil {
		return nil, fmt.Errorf("lookup api key: %w", err)
	}
	if revokedAt != nil || !expiresAt.After(s.now()) {
		return nil, ErrInvalidKey
	}

	s.touchLastUsed(hash)
	return &oidc.Claims{Subject: sub, Email: email}, nil
}

// List returns the caller's own keys, newest first.
func (s *Store) List(ctx context.Context, sub string) ([]Info, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, prefix, COALESCE(description,''), created_at, expires_at, revoked_at, last_used_at
		 FROM qw_api_keys WHERE principal_sub = $1 ORDER BY created_at DESC`, sub)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var out []Info
	for rows.Next() {
		var in Info
		if err := rows.Scan(&in.ID, &in.Prefix, &in.Description, &in.CreatedAt, &in.ExpiresAt, &in.RevokedAt, &in.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// Revoke marks the caller's key revoked. It is scoped to principal_sub so a user
// can only revoke their own keys. Revoking an unknown or already-revoked key
// returns ErrInvalidKey.
func (s *Store) Revoke(ctx context.Context, sub, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE qw_api_keys SET revoked_at = now()
		 WHERE id = $1 AND principal_sub = $2 AND revoked_at IS NULL`, id, sub)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidKey
	}
	return nil
}

// touchLastUsed updates last_used_at without blocking (or failing) the request.
// It uses a detached context so a cancelled request still records the use.
func (s *Store) touchLastUsed(hash string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.pool.Exec(ctx, `UPDATE qw_api_keys SET last_used_at = now() WHERE key_hash = $1`, hash)
	}()
}

func generateKey() (string, error) {
	b := make([]byte, keyRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	return KeyPrefix + hex.EncodeToString(b), nil
}

func hashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func nilStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
