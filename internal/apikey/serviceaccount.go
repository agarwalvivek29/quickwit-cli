package apikey

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ServiceAccountSubjectPrefix marks the principal of a service-account key, so
// the audit trail records `sa:<name>` instead of a person. OIDC subjects never
// carry it, which keeps service-account keys out of every user's `List`.
const ServiceAccountSubjectPrefix = "sa:"

var (
	// ErrServiceAccountNotFound is returned for an unknown service account, or a
	// disabled one where only an active account makes sense.
	ErrServiceAccountNotFound = errors.New("service account not found")
	// ErrServiceAccountExists is returned when creating a name that is taken
	// (including by a disabled account — names are never reused).
	ErrServiceAccountExists = errors.New("service account already exists")
	// ErrInvalidName is returned for a name outside nameRe.
	ErrInvalidName = errors.New("invalid service account name: use 2-63 lowercase letters, digits or '-', starting with a letter or digit")
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// ServiceAccount is a service account's metadata for listing.
type ServiceAccount struct {
	ID          string
	Name        string
	Description string
	CreatedBy   string // creating admin's email (or sub)
	CreatedAt   time.Time
	DisabledAt  *time.Time
	ActiveKeys  int        // unrevoked, unexpired keys
	LastUsedAt  *time.Time // most recent use across all of its keys
}

// StaleKey is an active service-account key nobody has used for a while.
type StaleKey struct {
	ServiceAccount string
	ID             string
	Prefix         string
	CreatedAt      time.Time
	LastUsedAt     *time.Time // nil = never used
}

// CreateServiceAccount registers a new service account on behalf of an admin.
func (s *Store) CreateServiceAccount(ctx context.Context, name, description, bySub, byEmail string) (*ServiceAccount, error) {
	if !nameRe.MatchString(name) {
		return nil, ErrInvalidName
	}
	if bySub == "" {
		return nil, errors.New("cannot create a service account without an admin subject")
	}
	sa := &ServiceAccount{Name: name, Description: description, CreatedBy: firstNonEmpty(byEmail, bySub)}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO qw_service_accounts (name, description, created_by_sub, created_by_email)
		 VALUES ($1,$2,$3,$4) RETURNING id::text, created_at`,
		name, nilStr(description), bySub, nilStr(byEmail),
	).Scan(&sa.ID, &sa.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return nil, ErrServiceAccountExists
	}
	if err != nil {
		return nil, fmt.Errorf("insert service account: %w", err)
	}
	return sa, nil
}

// ListServiceAccounts returns every service account (disabled ones included),
// with its active-key count and most recent key use.
func (s *Store) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT sa.id::text, sa.name, COALESCE(sa.description,''),
		        COALESCE(sa.created_by_email, sa.created_by_sub), sa.created_at, sa.disabled_at,
		        COUNT(k.id) FILTER (WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > $1)),
		        MAX(k.last_used_at)
		 FROM qw_service_accounts sa LEFT JOIN qw_api_keys k ON k.service_account_id = sa.id
		 GROUP BY sa.id ORDER BY sa.name`, s.now())
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()

	var out []ServiceAccount
	for rows.Next() {
		var sa ServiceAccount
		if err := rows.Scan(&sa.ID, &sa.Name, &sa.Description, &sa.CreatedBy, &sa.CreatedAt,
			&sa.DisabledAt, &sa.ActiveKeys, &sa.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

// DisableServiceAccount marks an active service account disabled, which
// immediately invalidates all of its keys (Authenticate checks disabled_at).
func (s *Store) DisableServiceAccount(ctx context.Context, name, bySub string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE qw_service_accounts SET disabled_at = now(), disabled_by_sub = $2
		 WHERE name = $1 AND disabled_at IS NULL`, name, bySub)
	if err != nil {
		return fmt.Errorf("disable service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrServiceAccountNotFound
	}
	return nil
}

// CreateServiceAccountKey mints a key for an active service account. ttl <= 0
// means the key never expires; the caller decides which lifetimes are allowed.
// The returned Created has a zero ExpiresAt for a non-expiring key.
func (s *Store) CreateServiceAccountKey(ctx context.Context, name, description string, ttl time.Duration, bySub, byEmail string) (*Created, error) {
	saID, err := s.activeServiceAccountID(ctx, name)
	if err != nil {
		return nil, err
	}
	raw, err := generateKey()
	if err != nil {
		return nil, err
	}
	var expiresAt *time.Time
	if ttl > 0 {
		t := s.now().UTC().Add(ttl)
		expiresAt = &t
	}
	var id string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO qw_api_keys (key_hash, prefix, principal_sub, description, expires_at,
		                          service_account_id, created_by_sub, created_by_email)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text`,
		hashKey(raw), raw[:prefixDisplayLen], ServiceAccountSubjectPrefix+name, nilStr(description),
		expiresAt, saID, bySub, nilStr(byEmail),
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert service account key: %w", err)
	}
	c := &Created{ID: id, APIKey: raw}
	if expiresAt != nil {
		c.ExpiresAt = *expiresAt
	}
	return c, nil
}

// ListServiceAccountKeys returns a service account's keys, newest first. It
// works for a disabled account too, so its history stays inspectable.
func (s *Store) ListServiceAccountKeys(ctx context.Context, name string) ([]Info, error) {
	var saID string
	err := s.pool.QueryRow(ctx, `SELECT id::text FROM qw_service_accounts WHERE name = $1`, name).Scan(&saID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup service account: %w", err)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, prefix, COALESCE(description,''), created_at, expires_at, revoked_at, last_used_at,
		        COALESCE(created_by_email, created_by_sub, '')
		 FROM qw_api_keys WHERE service_account_id = $1 ORDER BY created_at DESC`, saID)
	if err != nil {
		return nil, fmt.Errorf("list service account keys: %w", err)
	}
	return scanInfos(rows)
}

// RevokeServiceAccountKey revokes one key, scoped to the named service account
// so an id from another account can't be revoked by mistake. Unknown or
// already-revoked keys return ErrInvalidKey.
func (s *Store) RevokeServiceAccountKey(ctx context.Context, name, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE qw_api_keys k SET revoked_at = now()
		 FROM qw_service_accounts sa
		 WHERE k.service_account_id = sa.id AND sa.name = $1 AND k.id::text = $2 AND k.revoked_at IS NULL`,
		name, id)
	if err != nil {
		return fmt.Errorf("revoke service account key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidKey
	}
	return nil
}

// StaleServiceAccountKeys returns the active keys of active service accounts
// that have not been used within unusedFor (a never-used key counts from its
// creation). Personal keys are excluded: they expire within the max TTL anyway.
func (s *Store) StaleServiceAccountKeys(ctx context.Context, unusedFor time.Duration) ([]StaleKey, error) {
	now := s.now()
	rows, err := s.pool.Query(ctx,
		`SELECT sa.name, k.id::text, k.prefix, k.created_at, k.last_used_at
		 FROM qw_api_keys k JOIN qw_service_accounts sa ON sa.id = k.service_account_id
		 WHERE sa.disabled_at IS NULL AND k.revoked_at IS NULL
		   AND (k.expires_at IS NULL OR k.expires_at > $1)
		   AND COALESCE(k.last_used_at, k.created_at) < $2
		 ORDER BY sa.name, k.created_at`, now, now.Add(-unusedFor))
	if err != nil {
		return nil, fmt.Errorf("list stale service account keys: %w", err)
	}
	defer rows.Close()

	var out []StaleKey
	for rows.Next() {
		var k StaleKey
		if err := rows.Scan(&k.ServiceAccount, &k.ID, &k.Prefix, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan stale key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) activeServiceAccountID(ctx context.Context, name string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT id::text FROM qw_service_accounts WHERE name = $1 AND disabled_at IS NULL`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrServiceAccountNotFound
	}
	if err != nil {
		return "", fmt.Errorf("lookup service account: %w", err)
	}
	return id, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
