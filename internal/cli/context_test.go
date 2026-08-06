package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

func seedConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{
		CurrentContext: "stage",
		Contexts: []*config.Context{
			{Name: "stage", Endpoint: "http://stage:9000", OIDC: config.OIDCConfig{Issuer: "http://idp/stage", ClientID: "qw-cli"}},
			{Name: "local", Endpoint: "http://local:9000", OIDC: config.OIDCConfig{Issuer: "http://idp/local", ClientID: "qw-cli"}},
		},
	}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errb.String(), err
}

func TestContextListAndCurrent(t *testing.T) {
	path := seedConfig(t)

	out, _, err := runCmd(t, "--config", path, "context", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "stage") || !strings.Contains(out, "local") {
		t.Errorf("list missing contexts:\n%s", out)
	}
	// stage is current -> marked with *
	if !strings.Contains(out, "*") {
		t.Errorf("current marker missing:\n%s", out)
	}

	out, _, err = runCmd(t, "--config", path, "context", "current")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "stage" {
		t.Errorf("current = %q, want stage", out)
	}
}

func TestContextUsePersists(t *testing.T) {
	path := seedConfig(t)

	if _, _, err := runCmd(t, "--config", path, "context", "use", "local"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "local" {
		t.Errorf("current-context = %q, want local", cfg.CurrentContext)
	}

	// Using an unknown context should error.
	if _, _, err := runCmd(t, "--config", path, "context", "use", "ghost"); err == nil {
		t.Error("expected error using unknown context")
	}
}

func TestInvalidOutputRejected(t *testing.T) {
	path := seedConfig(t)
	if _, _, err := runCmd(t, "--config", path, "-o", "xml", "context", "current"); err == nil {
		t.Error("expected error for invalid --output")
	}
}

func TestContextCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	out, _, err := runCmd(t, "--config", path, "context", "create", "local",
		"--endpoint", "http://qwproxy:9000",
		"--issuer", "http://idp/realms/quickwit",
		"--client-id", "qw-cli",
		"--default-index", "core-logs",
		"--use")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Created context \"local\"") {
		t.Errorf("output = %q", out)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "local" || len(cfg.Contexts) != 1 {
		t.Fatalf("config = %+v", cfg)
	}
	c := cfg.Contexts[0]
	if c.Endpoint != "http://qwproxy:9000" || c.OIDC.Issuer != "http://idp/realms/quickwit" ||
		c.OIDC.ClientID != "qw-cli" || c.DefaultIndex != "core-logs" {
		t.Errorf("context = %+v", c)
	}
}

func TestContextCreateFirstBecomesCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// No --use, but it is the first context, so it must become current.
	if _, _, err := runCmd(t, "--config", path, "context", "create", "only", "--endpoint", "http://x"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(path)
	if cfg.CurrentContext != "only" {
		t.Errorf("first context should become current, got %q", cfg.CurrentContext)
	}
}

func TestContextCreateRequiresEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, _, err := runCmd(t, "--config", path, "context", "create", "local"); err == nil {
		t.Error("expected error when --endpoint is missing")
	}
}

func TestContextCreateUpdatePreservesToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := &config.Config{
		CurrentContext: "local",
		Contexts: []*config.Context{{
			Name:     "local",
			Endpoint: "http://old:9000",
			OIDC:     config.OIDCConfig{Issuer: "http://idp", ClientID: "qw-cli"},
			Auth:     &config.AuthTokens{AccessToken: "keep-me"},
		}},
	}
	if err := config.Save(path, seed); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCmd(t, "--config", path, "context", "create", "local", "--endpoint", "http://new:9000")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Updated context") {
		t.Errorf("expected 'Updated', got %q", out)
	}
	cfg, _ := config.Load(path)
	c := cfg.Contexts[0]
	if c.Endpoint != "http://new:9000" {
		t.Errorf("endpoint not updated: %q", c.Endpoint)
	}
	if c.Auth == nil || c.Auth.AccessToken != "keep-me" {
		t.Errorf("cached token not preserved on update: %+v", c.Auth)
	}
}

func TestContextDeleteClearsCurrent(t *testing.T) {
	path := seedConfig(t) // current = stage
	if _, _, err := runCmd(t, "--config", path, "context", "delete", "stage"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(path)
	if _, err := cfg.Context("stage"); err == nil {
		t.Error("stage context should be gone")
	}
	if cfg.CurrentContext != "" {
		t.Errorf("deleting the current context should clear current-context, got %q", cfg.CurrentContext)
	}
	// Deleting an unknown context errors.
	if _, _, err := runCmd(t, "--config", path, "context", "delete", "ghost"); err == nil {
		t.Error("expected error deleting unknown context")
	}
}

func TestConfigViewRedactsTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := &config.Config{
		CurrentContext: "local",
		Contexts: []*config.Context{{
			Name:     "local",
			Endpoint: "http://x:9000",
			OIDC:     config.OIDCConfig{Issuer: "http://idp", ClientID: "qw-cli"},
			Auth:     &config.AuthTokens{AccessToken: "super-secret-token", RefreshToken: "refresh-secret"},
		}},
	}
	if err := config.Save(path, seed); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCmd(t, "--config", path, "config", "view")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "super-secret-token") || strings.Contains(out, "refresh-secret") {
		t.Errorf("config view leaked a token:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("config view should mark redacted tokens:\n%s", out)
	}

	rawOut, _, err := runCmd(t, "--config", path, "config", "view", "--raw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rawOut, "super-secret-token") {
		t.Errorf("config view --raw should reveal the token:\n%s", rawOut)
	}
}

func TestWhoamiNotLoggedIn(t *testing.T) {
	path := seedConfig(t)
	out, _, err := runCmd(t, "--config", path, "--context", "local", "whoami")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not logged in") {
		t.Errorf("whoami = %q", out)
	}
}
