package apikey

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pgStore returns a Store on a fresh schema in the Postgres at QW_TEST_PG_DSN,
// skipping when it is unset. The schema starts as the 0.6.0 qw_api_keys table
// holding one personal key, so EnsureSchema is exercised as an upgrade.
func pgStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("QW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("QW_TEST_PG_DSN not set")
	}
	ctx := context.Background()
	schema := "qwtest_" + time.Now().Format("150405_000000")
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `CREATE TABLE qw_api_keys (
		id uuid PRIMARY KEY DEFAULT gen_random_uuid(), key_hash text NOT NULL UNIQUE,
		prefix text NOT NULL, principal_sub text NOT NULL, principal_email text, description text,
		created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
		revoked_at timestamptz, last_used_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	s := &Store{pool: pool, now: time.Now}
	for i := 0; i < 2; i++ { // idempotent
		if err := s.EnsureSchema(ctx); err != nil {
			t.Fatalf("EnsureSchema #%d: %v", i+1, err)
		}
	}
	return s
}

func TestPGServiceAccountLifecycle(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	personal, err := s.Create(ctx, "u1", "u1@example.com", "", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateServiceAccount(ctx, "Bad_Name", "", "a1", ""); !errors.Is(err, ErrInvalidName) {
		t.Errorf("bad name: err = %v, want ErrInvalidName", err)
	}
	if _, err := s.CreateServiceAccount(ctx, "triage-bot", "triage", "a1", "a1@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateServiceAccount(ctx, "triage-bot", "", "a1", ""); !errors.Is(err, ErrServiceAccountExists) {
		t.Errorf("duplicate: err = %v, want ErrServiceAccountExists", err)
	}

	never, err := s.CreateServiceAccountKey(ctx, "triage-bot", "prod", 0, "a1", "a1@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !never.ExpiresAt.IsZero() {
		t.Errorf("never key ExpiresAt = %s, want zero", never.ExpiresAt)
	}
	month, err := s.CreateServiceAccountKey(ctx, "triage-bot", "", 30*24*time.Hour, "a1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateServiceAccountKey(ctx, "ghost", "", 0, "a1", ""); !errors.Is(err, ErrServiceAccountNotFound) {
		t.Errorf("unknown sa: err = %v, want ErrServiceAccountNotFound", err)
	}

	claims, err := s.Authenticate(ctx, never.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "sa:triage-bot" || claims.Email != "" {
		t.Errorf("claims = %+v, want sa:triage-bot with no email", claims)
	}
	if _, err := s.Authenticate(ctx, personal.APIKey); err != nil {
		t.Errorf("pre-existing personal key stopped working: %v", err)
	}

	// Personal listing never shows service-account keys.
	mine, err := s.List(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].ExpiresAt == nil {
		t.Errorf("personal list = %+v, want 1 key with an expiry", mine)
	}

	keys, err := s.ListServiceAccountKeys(ctx, "triage-bot")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[1].ExpiresAt != nil || keys[1].CreatedBy != "a1@example.com" || keys[0].CreatedBy != "a1" {
		t.Errorf("sa keys = %+v", keys)
	}

	// Revoke is scoped to the named account.
	if _, err := s.CreateServiceAccount(ctx, "other-bot", "", "a1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeServiceAccountKey(ctx, "other-bot", month.ID); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("cross-account revoke: err = %v, want ErrInvalidKey", err)
	}
	if err := s.RevokeServiceAccountKey(ctx, "triage-bot", month.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, month.APIKey); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("revoked key: err = %v, want ErrInvalidKey", err)
	}

	sas, err := s.ListServiceAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sas) != 2 || sas[1].Name != "triage-bot" || sas[1].ActiveKeys != 1 || sas[1].CreatedBy != "a1@example.com" {
		t.Errorf("service accounts = %+v", sas)
	}

	// Disabling kills every key at once, and is not repeatable.
	if err := s.DisableServiceAccount(ctx, "triage-bot", "a1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, never.APIKey); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("key of disabled sa: err = %v, want ErrInvalidKey", err)
	}
	if err := s.DisableServiceAccount(ctx, "triage-bot", "a1"); !errors.Is(err, ErrServiceAccountNotFound) {
		t.Errorf("re-disable: err = %v, want ErrServiceAccountNotFound", err)
	}
	if _, err := s.CreateServiceAccountKey(ctx, "triage-bot", "", 0, "a1", ""); !errors.Is(err, ErrServiceAccountNotFound) {
		t.Errorf("mint on disabled sa: err = %v, want ErrServiceAccountNotFound", err)
	}
}

func TestPGStaleServiceAccountKeys(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	if _, err := s.CreateServiceAccount(ctx, "bot", "", "a1", ""); err != nil {
		t.Fatal(err)
	}
	k, err := s.CreateServiceAccountKey(ctx, "bot", "", 0, "a1", "")
	if err != nil {
		t.Fatal(err)
	}
	if stale, err := s.StaleServiceAccountKeys(ctx, 90*24*time.Hour); err != nil || len(stale) != 0 {
		t.Fatalf("fresh key reported stale: %+v, %v", stale, err)
	}

	// Look 100 days ahead: the never-used key is now stale.
	s.now = func() time.Time { return time.Now().Add(100 * 24 * time.Hour) }
	stale, err := s.StaleServiceAccountKeys(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].ID != k.ID || stale[0].ServiceAccount != "bot" || stale[0].LastUsedAt != nil {
		t.Errorf("stale = %+v, want the one never-used key", stale)
	}
}
