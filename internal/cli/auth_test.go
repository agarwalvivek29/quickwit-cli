package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// emptyConfig returns a --config path to a file that does not exist, so Load
// yields an empty Config and the test is isolated from the developer's real
// ~/.config/qw/config.yaml.
func emptyConfig(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "config.yaml")
}

func TestStaticTokenAuthReachesEndpoint(t *testing.T) {
	var gotAuth, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"build":{"version":"9.9.9"}}`))
	}))
	defer srv.Close()

	// No context at all — endpoint + token come purely from flags (the CI path).
	out, _, err := runCmd(t, "--config", emptyConfig(t), "--endpoint", srv.URL, "--token", "abc123", "ping")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer abc123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer abc123")
	}
	if !strings.HasPrefix(gotUA, "qw/") {
		t.Errorf("User-Agent = %q, want qw/*", gotUA)
	}
	if !strings.Contains(out, "9.9.9") {
		t.Errorf("ping output missing version: %q", out)
	}
}

func TestNoContextNoEndpointErrors(t *testing.T) {
	_, _, err := runCmd(t, "--config", emptyConfig(t), "ping")
	if err == nil {
		t.Fatal("expected an error with no context and no endpoint")
	}
	if !strings.Contains(err.Error(), "no context") {
		t.Errorf("error = %v, want a 'no context' message", err)
	}
}

func TestEndpointWithoutCredentialErrors(t *testing.T) {
	// Ephemeral endpoint but no token/secret and no cached login.
	_, _, err := runCmd(t, "--config", emptyConfig(t), "--endpoint", "http://x", "ping")
	if err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("error = %v, want 'not logged in ...'", err)
	}
}

func TestClientSecretNeedsIssuer(t *testing.T) {
	// Ephemeral context has no issuer/client-id (QW_ISSUER unset), so
	// client-credentials must be rejected before any network call.
	_, _, err := runCmd(t, "--config", emptyConfig(t), "--endpoint", "http://x", "--client-secret", "s", "ping")
	if err == nil || !strings.Contains(err.Error(), "issuer and client-id") {
		t.Errorf("error = %v, want an issuer/client-id requirement", err)
	}
}

func TestRenderJQProjectsHits(t *testing.T) {
	var buf bytes.Buffer
	a := &App{JQ: ".[].message", Out: &buf, Err: &bytes.Buffer{}}
	hits := []json.RawMessage{
		json.RawMessage(`{"message":"first","level":"INFO"}`),
		json.RawMessage(`{"message":"second","level":"ERROR"}`),
	}
	if err := a.renderHits(hits); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, `"first"`) || !strings.Contains(got, `"second"`) {
		t.Errorf("jq output = %q, want both messages", got)
	}
	if strings.Contains(got, "level") {
		t.Errorf("jq should have projected only .message, got %q", got)
	}
}

func TestRenderJQInvalidExpression(t *testing.T) {
	a := &App{JQ: ".[", Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if err := a.renderHits([]json.RawMessage{json.RawMessage(`{}`)}); err == nil {
		t.Error("expected a parse error for an invalid --jq expression")
	}
}
