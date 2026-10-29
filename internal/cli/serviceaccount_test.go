package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

type saCall struct {
	method, path string
	query        map[string]string
	body         map[string]any
	auth         string
}

// saServer records each request and answers with resp (may be nil → 204).
func saServer(t *testing.T, resp any) (*httptest.Server, *[]saCall) {
	t.Helper()
	var calls []saCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := saCall{method: r.Method, path: r.URL.Path, query: map[string]string{}, auth: r.Header.Get("Authorization")}
		for k := range r.URL.Query() {
			c.query[k] = r.URL.Query().Get(k)
		}
		_ = json.NewDecoder(r.Body).Decode(&c.body)
		calls = append(calls, c)
		if resp == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestSAKeyCreateNeverExpiringNotSaved(t *testing.T) {
	srv, calls := saServer(t, map[string]any{"id": "k-1", "api_key": "qw_pat_agent", "expires_at": nil})
	path := configWith(t, srv.URL, "", time.Time{})

	out, _, err := runCmd(t, "--config", path, "--token", "tok", "sa", "key", "create", "triage-bot", "--ttl", "never")
	if err != nil {
		t.Fatal(err)
	}
	c := (*calls)[0]
	if c.method != http.MethodPost || c.path != "/qwproxy/serviceaccounts" || c.query["name"] != "triage-bot" {
		t.Errorf("request = %s %s %v, want POST /qwproxy/serviceaccounts?name=triage-bot", c.method, c.path, c.query)
	}
	if c.body["ttl"] != "never" {
		t.Errorf("body ttl = %v, want never", c.body["ttl"])
	}
	if c.auth != "Bearer tok" {
		t.Errorf("Authorization = %q, want the OIDC bearer", c.auth)
	}
	if !strings.Contains(out, "qw_pat_agent") || !strings.Contains(out, "expires: never") {
		t.Errorf("output = %q, want the key and 'expires: never'", out)
	}

	// The agent's key is for the agent, not the admin's own context.
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cctx, _ := cfg.Context("test")
	if cctx.Auth != nil && cctx.Auth.APIKey != "" {
		t.Errorf("service-account key was saved to the admin's context: %+v", cctx.Auth)
	}
}

func TestSAKeyCreateRequiresTTL(t *testing.T) {
	srv, calls := saServer(t, nil)
	path := configWith(t, srv.URL, "", time.Time{})
	if _, _, err := runCmd(t, "--config", path, "--token", "tok", "sa", "key", "create", "bot"); err == nil {
		t.Fatal("expected an error without --ttl")
	}
	if len(*calls) != 0 {
		t.Errorf("request sent without --ttl: %+v", *calls)
	}
}

// Every service-account call stays on the base path (query params only) so a
// gateway routing just /qwproxy/serviceaccounts handles all of them.
func TestSACommandsUseBasePathOnly(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		want  string
		query map[string]string
	}{
		{[]string{"sa", "create", "bot", "--description", "d"}, http.MethodPost, map[string]string{}},
		{[]string{"sa", "disable", "bot"}, http.MethodDelete, map[string]string{"name": "bot"}},
		{[]string{"sa", "key", "revoke", "bot", "k-9"}, http.MethodDelete, map[string]string{"name": "bot", "key_id": "k-9"}},
	} {
		srv, calls := saServer(t, map[string]any{"id": "sa-1", "name": "bot"})
		path := configWith(t, srv.URL, "", time.Time{})
		if _, _, err := runCmd(t, append([]string{"--config", path, "--token", "tok"}, tc.args...)...); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		c := (*calls)[0]
		if c.method != tc.want || c.path != "/qwproxy/serviceaccounts" {
			t.Errorf("%v: request = %s %s, want %s /qwproxy/serviceaccounts", tc.args, c.method, c.path, tc.want)
		}
		for k, v := range tc.query {
			if c.query[k] != v {
				t.Errorf("%v: query %s = %q, want %q", tc.args, k, c.query[k], v)
			}
		}
		if len(c.query) != len(tc.query) {
			t.Errorf("%v: query = %v, want %v", tc.args, c.query, tc.query)
		}
	}
}

func TestKeyStatus(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	day := 24 * time.Hour
	for _, tc := range []struct {
		name                 string
		expires, revoked, lu *time.Time
		created              time.Time
		want                 string
	}{
		{"fresh never-expiring", nil, nil, nil, now.Add(-day), "active"},
		{"used recently", nil, nil, ago(day), now.Add(-200 * day), "active"},
		{"unused 91d", nil, nil, ago(91 * day), now.Add(-200 * day), "stale"},
		{"never used, old", nil, nil, nil, now.Add(-100 * day), "stale"},
		{"expired", ago(day), nil, nil, now.Add(-10 * day), "expired"},
		{"revoked", nil, ago(day), nil, now.Add(-10 * day), "revoked"},
	} {
		if got := keyStatus(now, tc.expires, tc.revoked, tc.lu, tc.created); got != tc.want {
			t.Errorf("%s: status = %q, want %q", tc.name, got, tc.want)
		}
	}
}
