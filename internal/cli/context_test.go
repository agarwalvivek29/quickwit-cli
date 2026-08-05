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
