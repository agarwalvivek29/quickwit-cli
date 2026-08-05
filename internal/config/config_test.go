package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	in := &Config{
		CurrentContext: "local",
		Contexts: []*Context{
			{
				Name:         "local",
				Endpoint:     "http://localhost:9000",
				OIDC:         OIDCConfig{Issuer: "http://localhost:8080/realms/quickwit", ClientID: "qw-cli"},
				DefaultIndex: "core-logs",
				Auth:         &AuthTokens{AccessToken: "abc", RefreshToken: "ref"},
			},
		},
	}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.CurrentContext != "local" || len(out.Contexts) != 1 {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	ctx := out.Contexts[0]
	if ctx.Endpoint != in.Contexts[0].Endpoint || ctx.OIDC.ClientID != "qw-cli" {
		t.Errorf("context mismatch: %+v", ctx)
	}
	if ctx.Auth == nil || ctx.Auth.AccessToken != "abc" {
		t.Errorf("auth not persisted: %+v", ctx.Auth)
	}
}

func TestSaveIs0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, &Config{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(c.Contexts) != 0 || c.CurrentContext != "" {
		t.Errorf("expected empty config, got %+v", c)
	}
}

func TestResolvePrecedence(t *testing.T) {
	c := &Config{
		CurrentContext: "stage",
		Contexts: []*Context{
			{Name: "stage"}, {Name: "local"},
		},
	}
	// Override wins over current-context.
	got, err := c.Resolve("local")
	if err != nil || got.Name != "local" {
		t.Errorf("override resolve = %v, %v", got, err)
	}
	// Empty override falls back to current-context.
	got, err = c.Resolve("")
	if err != nil || got.Name != "stage" {
		t.Errorf("current resolve = %v, %v", got, err)
	}
	// Unknown override errors.
	if _, err := c.Resolve("nope"); err == nil {
		t.Error("expected error for unknown context")
	}
}

func TestResolveNoContext(t *testing.T) {
	if _, err := (&Config{}).Resolve(""); err != ErrNoContext {
		t.Errorf("err = %v, want ErrNoContext", err)
	}
}

func TestUpsertAndUse(t *testing.T) {
	c := &Config{}
	c.Upsert(&Context{Name: "local", Endpoint: "a"})
	c.Upsert(&Context{Name: "local", Endpoint: "b"}) // replace, not append
	if len(c.Contexts) != 1 || c.Contexts[0].Endpoint != "b" {
		t.Fatalf("upsert replace failed: %+v", c.Contexts)
	}
	if err := c.Use("local"); err != nil || c.CurrentContext != "local" {
		t.Errorf("use failed: %v", err)
	}
	if err := c.Use("ghost"); err == nil {
		t.Error("use of unknown context should error")
	}
}

func TestDefaultPathHonorsEnv(t *testing.T) {
	t.Setenv(EnvConfigPath, "/custom/qw.yaml")
	p, err := DefaultPath()
	if err != nil || p != "/custom/qw.yaml" {
		t.Errorf("path = %q, %v", p, err)
	}

	t.Setenv(EnvConfigPath, "")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	p, err = DefaultPath()
	if err != nil || p != "/xdg/qw/config.yaml" {
		t.Errorf("xdg path = %q, %v", p, err)
	}
}
