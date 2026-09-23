package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// stubKeyAuth authorizes exactly the key "valid-key".
type stubKeyAuth struct{}

func (stubKeyAuth) Authenticate(_ context.Context, raw string) (*oidc.Claims, error) {
	if raw == "valid-key" {
		return &oidc.Claims{Subject: "svc1", Email: "svc1@example.com"}, nil
	}
	return nil, errThrottle
}

var errThrottle = &authErr{"invalid"}

type authErr struct{ s string }

func (e *authErr) Error() string { return e.s }

func handlerWithKeys(t *testing.T, up *upstream, ca *capAudit, ka APIKeyAuthenticator) *Handler {
	t.Helper()
	h := newHandler(t, up, ca)
	h.opts.APIKeys = ka
	return h
}

func doKey(h *Handler, method, path, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if key != "" {
		r.Header.Set(apiKeyHeader, key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIKeyValidForwardsAndAudits(t *testing.T) {
	up := newUpstream(t)
	ca := &capAudit{}
	h := handlerWithKeys(t, up, ca, stubKeyAuth{})

	w := doKey(h, http.MethodGet, "/api/v1/indexes", "valid-key")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if up.hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", up.hits)
	}
	rec, ok := ca.last()
	if !ok {
		t.Fatal("no audit record")
	}
	if rec.AuthMethod != "api-key" {
		t.Errorf("audit AuthMethod = %q, want api-key", rec.AuthMethod)
	}
	if rec.PrincipalSub != "svc1" {
		t.Errorf("audit PrincipalSub = %q, want svc1", rec.PrincipalSub)
	}
}

func TestAPIKeyInvalidIs401(t *testing.T) {
	up := newUpstream(t)
	h := handlerWithKeys(t, up, &capAudit{}, stubKeyAuth{})

	w := doKey(h, http.MethodGet, "/api/v1/indexes", "nope")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if up.hits != 0 {
		t.Fatalf("upstream was hit with an invalid key")
	}
}

func TestAPIKeyDisabledWhenNoStore(t *testing.T) {
	up := newUpstream(t)
	h := newHandler(t, up, &capAudit{}) // Options.APIKeys is nil

	w := doKey(h, http.MethodGet, "/api/v1/indexes", "valid-key")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when api keys disabled", w.Code)
	}
}

// An X-API-Key must be tried first: a valid key succeeds even alongside a bogus
// Authorization header (and the OIDC verifier is never consulted).
func TestAPIKeyTakesPrecedenceOverBearer(t *testing.T) {
	up := newUpstream(t)
	h := handlerWithKeys(t, up, &capAudit{}, stubKeyAuth{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/indexes", nil)
	r.Header.Set(apiKeyHeader, "valid-key")
	r.Header.Set("Authorization", "Bearer this-would-fail")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (key should win)", w.Code)
	}
}
