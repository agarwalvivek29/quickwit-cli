package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/agarwalvivek29/quickwit-cli/internal/audit"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

type stubVerifier struct{}

func (stubVerifier) Verify(_ context.Context, raw string) (*oidc.Claims, error) {
	if raw == "good" {
		return &oidc.Claims{Subject: "u1", Email: "u1@example.com"}, nil
	}
	return nil, errors.New("bad token")
}

type capAudit struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (c *capAudit) Log(r audit.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
}
func (c *capAudit) last() (audit.Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.recs) == 0 {
		return audit.Record{}, false
	}
	return c.recs[len(c.recs)-1], true
}

// upstream captures the last forwarded request and returns a canned body.
type upstream struct {
	srv        *httptest.Server
	mu         sync.Mutex
	hits       int
	lastMethod string
	lastPath   string
	lastBody   string
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.hits++
		u.lastMethod, u.lastPath, u.lastBody = r.Method, r.URL.Path, string(b)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"num_hits":0,"hits":[]}`)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func newHandler(t *testing.T, up *upstream, ca *capAudit) *Handler {
	u, err := url.Parse(up.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Upstream: u, Verifier: stubVerifier{}, Audit: ca})
}

func do(h *Handler, method, path, token, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMissingToken401(t *testing.T) {
	up := newUpstream(t)
	h := newHandler(t, up, &capAudit{})
	w := do(h, http.MethodGet, "/api/v1/version", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
	if up.hits != 0 {
		t.Error("upstream should not be hit without auth")
	}
}

func TestInvalidToken401(t *testing.T) {
	up := newUpstream(t)
	h := newHandler(t, up, &capAudit{})
	w := do(h, http.MethodGet, "/api/v1/version", "nope", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
	if up.hits != 0 {
		t.Error("upstream should not be hit with a bad token")
	}
}

func TestAllowedRequestForwardsAndAudits(t *testing.T) {
	up := newUpstream(t)
	ca := &capAudit{}
	h := newHandler(t, up, ca)
	w := do(h, http.MethodGet, "/api/v1/version", "good", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	if up.hits != 1 || up.lastPath != "/api/v1/version" {
		t.Errorf("upstream not forwarded correctly: hits=%d path=%s", up.hits, up.lastPath)
	}
	rec, ok := ca.last()
	if !ok {
		t.Fatal("no audit record")
	}
	if rec.PrincipalEmail != "u1@example.com" || rec.Method != http.MethodGet || rec.StatusCode != 200 {
		t.Errorf("audit record = %+v", rec)
	}
	if rec.BytesOut == 0 {
		t.Error("expected non-zero bytes_out")
	}
}

func TestReadOnlyAllowlist(t *testing.T) {
	up := newUpstream(t)
	h := newHandler(t, up, &capAudit{})

	blocked := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/core-logs/ingest"},
		{http.MethodDelete, "/api/v1/indexes/core-logs"},
		{http.MethodPut, "/api/v1/indexes"},
		{http.MethodPost, "/api/v1/indexes"},
		{http.MethodGet, "/api/v1/indexes/core-logs/clear"},
	}
	for _, b := range blocked {
		w := do(h, b.method, b.path, "good", "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: code = %d, want 403", b.method, b.path, w.Code)
		}
	}
	if up.hits != 0 {
		t.Errorf("blocked requests reached upstream (%d hits)", up.hits)
	}
}

func TestSearchCapturesQueryBody(t *testing.T) {
	up := newUpstream(t)
	ca := &capAudit{}
	h := newHandler(t, up, ca)
	body := `{"query":"level:ERROR","max_hits":10}`
	w := do(h, http.MethodPost, "/api/v1/core-logs/search", "good", body)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	// Body must still reach upstream intact after being captured.
	if up.lastBody != body {
		t.Errorf("upstream body = %q, want %q", up.lastBody, body)
	}
	rec, _ := ca.last()
	if string(rec.QueryBody) != body {
		t.Errorf("audit query_body = %q, want %q", rec.QueryBody, body)
	}
	if rec.Index != "core-logs" {
		t.Errorf("audit index = %q, want core-logs", rec.Index)
	}
}

func TestClientIPFromXFF(t *testing.T) {
	up := newUpstream(t)
	ca := &capAudit{}
	h := newHandler(t, up, ca)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	r.Header.Set("Authorization", "Bearer good")
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	rec, _ := ca.last()
	if rec.ClientIP != "203.0.113.7" {
		t.Errorf("client ip = %q, want 203.0.113.7", rec.ClientIP)
	}
}

func TestIndexFromPath(t *testing.T) {
	cases := map[string]string{
		"/api/v1/a,b/search":                 "a,b",
		"/api/v1/indexes/core-logs":          "core-logs",
		"/api/v1/indexes/core-logs/describe": "core-logs",
		"/api/v1/version":                    "",
	}
	for path, want := range cases {
		if got := indexFromPath(path); got != want {
			t.Errorf("indexFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}
