package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

// configWith writes a single-context config pointing at endpoint, optionally with
// a stored API key + expiry, and returns its path.
func configWith(t *testing.T, endpoint, apiKey string, expiry time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cctx := &config.Context{
		Name:     "test",
		Endpoint: endpoint,
		OIDC:     config.OIDCConfig{Issuer: "http://idp/test", ClientID: "qw-cli"},
	}
	if apiKey != "" {
		cctx.Auth = &config.AuthTokens{APIKey: apiKey, APIKeyExpiry: expiry}
	}
	cfg := &config.Config{CurrentContext: "test", Contexts: []*config.Context{cctx}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStoredAPIKeySentAsHeader(t *testing.T) {
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"build":{"version":"9.9.9"}}`))
	}))
	defer srv.Close()

	path := configWith(t, srv.URL, "qw_pat_stored", time.Now().Add(24*time.Hour))
	if _, _, err := runCmd(t, "--config", path, "ping"); err != nil {
		t.Fatal(err)
	}
	if gotKey != "qw_pat_stored" {
		t.Errorf("X-API-Key = %q, want qw_pat_stored", gotKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty (key mode attaches no bearer)", gotAuth)
	}
}

func TestStaticTokenBeatsStoredAPIKey(t *testing.T) {
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"build":{"version":"9.9.9"}}`))
	}))
	defer srv.Close()

	path := configWith(t, srv.URL, "qw_pat_stored", time.Now().Add(24*time.Hour))
	if _, _, err := runCmd(t, "--config", path, "--token", "abc123", "ping"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer abc123" {
		t.Errorf("Authorization = %q, want Bearer abc123", gotAuth)
	}
	if gotKey != "" {
		t.Errorf("X-API-Key = %q, want empty when --token is given", gotKey)
	}
}

func TestExpiredAPIKeyFallsBackToOIDC(t *testing.T) {
	path := configWith(t, "http://unused:9000", "qw_pat_old", time.Now().Add(-time.Hour))
	// No login tokens are stored, so the OIDC fallback fails with "not logged in".
	_, errOut, err := runCmd(t, "--config", path, "ping")
	if err == nil {
		t.Fatal("expected an error falling back to OIDC with no login")
	}
	if !strings.Contains(errOut, "expired") {
		t.Errorf("stderr = %q, want an expiry warning", errOut)
	}
	if !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("error = %v, want 'not logged in'", err)
	}
}

func TestAPIKeyCreateSavesToConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/qwproxy/apikeys" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "id-9",
			"api_key":    "qw_pat_minted",
			"expires_at": time.Now().Add(15 * 24 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	path := configWith(t, srv.URL, "", time.Time{})
	// --token forces the OIDC/bearer path for the mint call (no real login in tests).
	out, _, err := runCmd(t, "--config", path, "--token", "tok", "apikey", "create", "--ttl-days", "15")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "qw_pat_minted") {
		t.Errorf("output missing the minted key: %q", out)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cctx, err := cfg.Context("test")
	if err != nil {
		t.Fatal(err)
	}
	if cctx.Auth == nil || cctx.Auth.APIKey != "qw_pat_minted" {
		t.Fatalf("config was not updated with the minted key: %+v", cctx.Auth)
	}
}

// Revoke must target the base path with ?id= (not /qwproxy/apikeys/{id}), so it
// works behind a gateway that only routes the base path.
func TestAPIKeyRevokeUsesBasePathQuery(t *testing.T) {
	var gotMethod, gotPath, gotID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotID = r.Method, r.URL.Path, r.URL.Query().Get("id")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	path := configWith(t, srv.URL, "", time.Time{})
	if _, _, err := runCmd(t, "--config", path, "--token", "tok", "apikey", "revoke", "abc-123"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/qwproxy/apikeys" {
		t.Errorf("path = %q, want /qwproxy/apikeys (base path, no sub-path)", gotPath)
	}
	if gotID != "abc-123" {
		t.Errorf("id query = %q, want abc-123", gotID)
	}
}
