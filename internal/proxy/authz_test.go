package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// signingOP is a minimal OIDC provider — just discovery + JWKS, enough for the
// resource-server verifier — that signs tokens with a local RSA key so a test
// can drive the full signature + aud path through the real oidc.Verifier.
type signingOP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	issuer string
}

func newSigningOP(t *testing.T) *signingOP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	op := &signingOP{key: key, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                op.issuer,
			"authorization_endpoint":                op.issuer + "/authorize",
			"token_endpoint":                        op.issuer + "/token",
			"jwks_uri":                              op.issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": op.kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	op.issuer = op.srv.URL
	return op
}

// token mints an RS256 JWT with the given audience (an ID token stands in: aud =
// the app's client id).
func (op *signingOP) token(t *testing.T, aud string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   op.issuer,
		"sub":   "u1",
		"email": "u1@example.com",
		"aud":   aud,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})
	tok.Header["kid"] = op.kid
	s, err := tok.SignedString(op.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestProxyEnforcesAudience is the load-bearing access-control check Tanmay
// flagged: with the proxy pinned to a client id, a token whose aud is a
// DIFFERENT app/env (a stage token replayed at the prod proxy) is rejected at
// the door with 401 and never reaches the upstream — while a token with the
// right aud passes. This wires the real oidc.Verifier into the handler so a
// refactor that silently drops the aud check fails here.
func TestProxyEnforcesAudience(t *testing.T) {
	op := newSigningOP(t)
	ctx := context.Background()
	const thisApp = "qw-prod"

	v, err := oidc.NewVerifier(ctx, op.issuer, thisApp, oidc.Options{})
	if err != nil {
		t.Fatal(err)
	}

	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	h := New(Options{Upstream: u, Verifier: v, Audit: &capAudit{}})

	// Wrong aud (token minted for another app/env) → 401, no upstream hit.
	w := do(h, http.MethodGet, "/api/v1/version", op.token(t, "qw-stage"), "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong-aud token: code = %d, want 401", w.Code)
	}
	if up.hits != 0 {
		t.Errorf("wrong-aud token reached upstream (%d hits)", up.hits)
	}

	// Right aud → 200, forwarded.
	w = do(h, http.MethodGet, "/api/v1/version", op.token(t, thisApp), "")
	if w.Code != http.StatusOK {
		t.Errorf("correct-aud token: code = %d, want 200", w.Code)
	}
	if up.hits != 1 {
		t.Errorf("correct-aud token not forwarded (hits=%d)", up.hits)
	}
}
