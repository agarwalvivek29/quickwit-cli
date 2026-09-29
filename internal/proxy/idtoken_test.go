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
