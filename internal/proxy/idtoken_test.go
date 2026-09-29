package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// doGrafana mimics Grafana oauthPassThru: access token as the bearer, ID token
// in X-ID-Token.
func doGrafana(h *Handler, bearer, idToken string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if idToken != "" {
		r.Header.Set(idTokenHeader, idToken)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestIDTokenFallback(t *testing.T) {
	cases := []struct {
		name, bearer, idToken string
		wantCode              int
		wantMethod            string
	}{
		{"rejected bearer, valid id token", "org-access-token", "good", http.StatusOK, "oidc-id-token"},
		{"id token only", "", "good", http.StatusOK, "oidc-id-token"},
		{"valid bearer wins", "good", "bad", http.StatusOK, "oidc"},
		{"both rejected", "org-access-token", "bad", http.StatusUnauthorized, ""},
		{"id token rejected, no bearer", "", "bad", http.StatusUnauthorized, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newUpstream(t)
			ca := &capAudit{}
			h := newHandler(t, up, ca)
			w := doGrafana(h, tc.bearer, tc.idToken)
			if w.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", w.Code, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				if up.hits != 0 {
					t.Error("upstream hit with rejected credentials")
				}
				return
			}
			rec, ok := ca.last()
			if !ok {
				t.Fatal("no audit record")
			}
			if rec.AuthMethod != tc.wantMethod {
				t.Errorf("AuthMethod = %q, want %q", rec.AuthMethod, tc.wantMethod)
			}
			if rec.PrincipalSub != "u1" {
				t.Errorf("PrincipalSub = %q, want u1", rec.PrincipalSub)
			}
		})
	}
}

// Grafana's background init call carries only the datasource's X-API-Key, while
// user queries carry the key plus the user's tokens; the user must win.
func TestUserTokenPreferredOverAPIKey(t *testing.T) {
	cases := []struct {
		name, bearer, idToken, key string
		wantCode                   int
		wantMethod, wantSub        string
	}{
		{"key + valid id token", "org-access-token", "good", "valid-key", http.StatusOK, "oidc-id-token", "u1"},
		{"key + valid bearer", "good", "", "valid-key", http.StatusOK, "oidc", "u1"},
		{"key only (grafana init)", "", "", "valid-key", http.StatusOK, "api-key", "svc1"},
		{"key + rejected tokens", "org-access-token", "bad", "valid-key", http.StatusOK, "api-key", "svc1"},
		{"invalid key + rejected tokens", "org-access-token", "bad", "nope", http.StatusUnauthorized, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newUpstream(t)
			ca := &capAudit{}
			h := handlerWithKeys(t, up, ca, stubKeyAuth{})
			r := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
			if tc.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.idToken != "" {
				r.Header.Set(idTokenHeader, tc.idToken)
			}
			r.Header.Set(apiKeyHeader, tc.key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", w.Code, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				if up.hits != 0 {
					t.Error("upstream hit with rejected credentials")
				}
				return
			}
			rec, _ := ca.last()
			if rec.AuthMethod != tc.wantMethod || rec.PrincipalSub != tc.wantSub {
				t.Errorf("audit = (%q, %q), want (%q, %q)", rec.AuthMethod, rec.PrincipalSub, tc.wantMethod, tc.wantSub)
			}
		})
	}
}
