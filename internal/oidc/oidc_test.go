package oidc

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
)

// mockOP is a minimal OIDC provider: discovery + JWKS + token + device
// endpoints, signing tokens with a local RSA key so tests can verify the full
// signature path.
type mockOP struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	kid          string
	issuer       string
	clientID     string
	audience     string
	lastVerifier string // code_verifier seen at /token (proves PKCE wiring)
}

func newMockOP(t *testing.T) *mockOP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockOP{key: key, kid: "test-key", clientID: "qw-cli", audience: "quickwit-api"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                m.issuer,
			"authorization_endpoint":                m.issuer + "/authorize",
			"token_endpoint":                        m.issuer + "/token",
			"jwks_uri":                              m.issuer + "/jwks",
			"device_authorization_endpoint":         m.issuer + "/device",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.jwks())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.lastVerifier = r.Form.Get("code_verifier")
		grant := r.Form.Get("grant_type")
		access := m.mint(t, m.audience, time.Now().Add(time.Hour), "user-123", "dev@example.com")
		if grant == "refresh_token" {
			// A refresh returns a *different* access token so tests can detect it.
			access = m.mint(t, m.audience, time.Now().Add(2*time.Hour), "user-123", "dev@example.com")
		}
		id := m.mint(t, m.clientID, time.Now().Add(time.Hour), "user-123", "dev@example.com")
		writeJSON(w, map[string]any{
			"access_token":  access,
			"id_token":      id,
			"refresh_token": "refresh-abc",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"device_code":      "dev-code",
			"user_code":        "WXYZ-1234",
			"verification_uri": m.issuer + "/activate",
			"expires_in":       600,
			"interval":         1,
		})
	})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	m.issuer = m.srv.URL
	return m
}

func (m *mockOP) jwks() map[string]any {
	pub := m.key.Public().(*rsa.PublicKey)
	return map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"kid": m.kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

func (m *mockOP) mint(t *testing.T, aud string, exp time.Time, sub, email string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   m.issuer,
		"sub":   sub,
		"email": email,
		"aud":   aud,
		"exp":   exp.Unix(),
		"iat":   time.Now().Unix(),
	})
	tok.Header["kid"] = m.kid
	s, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestVerifierValidToken(t *testing.T) {
	m := newMockOP(t)
	ctx := context.Background()
	v, err := NewVerifier(ctx, m.issuer, m.audience, Options{})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Verify(ctx, m.mint(t, m.audience, time.Now().Add(time.Hour), "user-123", "dev@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-123" || claims.Email != "dev@example.com" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifierRejects(t *testing.T) {
	m := newMockOP(t)
	ctx := context.Background()
	v, err := NewVerifier(ctx, m.issuer, m.audience, Options{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired", func(t *testing.T) {
		if _, err := v.Verify(ctx, m.mint(t, m.audience, time.Now().Add(-time.Hour), "u", "e")); err == nil {
			t.Error("expected error for expired token")
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		if _, err := v.Verify(ctx, m.mint(t, "some-other-api", time.Now().Add(time.Hour), "u", "e")); err == nil {
			t.Error("expected error for wrong audience")
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		good := m.mint(t, m.audience, time.Now().Add(time.Hour), "u", "e")
		bad := good[:len(good)-3] + "AAA"
		if _, err := v.Verify(ctx, bad); err == nil {
			t.Error("expected error for tampered token")
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "https://evil.example", "sub": "u", "aud": m.audience,
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = m.kid
		s, _ := tok.SignedString(m.key)
		if _, err := v.Verify(ctx, s); err == nil {
			t.Error("expected error for wrong issuer")
		}
	})
}

// TestVerifierGatewayOverride reproduces an isolated network: the token's real
// issuer host is unreachable, only an internal gateway can be reached, and the
// gateway's discovery document advertises that unreachable issuer. Plain
// discovery must fail on the issuer/URL mismatch; the DiscoveryURL+JWKSURL
// override must adopt the advertised issuer and validate the token via the
// gateway.
func TestVerifierGatewayOverride(t *testing.T) {
	m := newMockOP(t)
	ctx := context.Background()
	gateway := m.srv.URL // the only reachable endpoint (the internal proxy)
	// Make the advertised issuer + minted `iss` a value that is NOT the URL the
	// discovery doc is served from — exactly what a path/custom-domain issuer
	// behind a proxy looks like.
	m.issuer = "https://idp.unreachable.test"

	// Plain discovery against the gateway fails: doc issuer != fetch URL.
	if _, err := NewVerifier(ctx, gateway, m.audience, Options{}); err == nil {
		t.Fatal("expected plain discovery to fail on issuer/URL mismatch")
	}

	// Override: fetch discovery + JWKS via the gateway, adopt the advertised
	// issuer (leave issuer empty), and validate a token whose iss is unreachable.
	v, err := NewVerifier(ctx, "", m.audience, Options{
		DiscoveryURL: gateway,
		JWKSURL:      gateway + "/jwks",
	})
	if err != nil {
		t.Fatalf("gateway-override NewVerifier: %v", err)
	}
	claims, err := v.Verify(ctx, m.mint(t, m.audience, time.Now().Add(time.Hour), "user-123", "dev@example.com"))
	if err != nil {
		t.Fatalf("verify via gateway override: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "dev@example.com" {
		t.Errorf("claims = %+v", claims)
	}

	// A token from a different issuer must still be rejected under the override.
	bad := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://someone.else.test", "sub": "u", "aud": m.audience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	bad.Header["kid"] = m.kid
	bs, _ := bad.SignedString(m.key)
	if _, err := v.Verify(ctx, bs); err == nil {
		t.Error("expected error for token from a different issuer")
	}
}

func TestLoginPKCE(t *testing.T) {
	m := newMockOP(t)
	ctx := context.Background()
	a, err := New(ctx, ProviderConfig{Issuer: m.issuer, ClientID: m.clientID, Audience: m.audience})
	if err != nil {
		t.Fatal(err)
	}
	// Simulated browser: assert PKCE params, then drive the loopback callback.
	a.Opener = func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		q := u.Query()
		if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
			t.Errorf("missing PKCE challenge: %v", q)
		}
		redir := q.Get("redirect_uri")
		state := q.Get("state")
		go func() {
			resp, err := http.Get(redir + "?code=fakecode&state=" + url.QueryEscape(state))
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}

	toks, err := a.Login(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if toks.AccessToken == "" || toks.RefreshToken != "refresh-abc" || toks.IDToken == "" {
		t.Errorf("tokens = %+v", toks)
	}
	if m.lastVerifier == "" {
		t.Error("token endpoint did not receive a PKCE code_verifier")
	}
}

func TestLoginDevice(t *testing.T) {
	m := newMockOP(t)
	ctx := context.Background()
	a, err := New(ctx, ProviderConfig{Issuer: m.issuer, ClientID: m.clientID, Audience: m.audience})
	if err != nil {
		t.Fatal(err)
	}
	var prompted DevicePrompt
	toks, err := a.LoginDevice(ctx, func(p DevicePrompt) { prompted = p })
	if err != nil {
		t.Fatal(err)
	}
	if prompted.UserCode != "WXYZ-1234" {
		t.Errorf("prompt = %+v", prompted)
	}
	if toks.AccessToken == "" {
		t.Error("no access token from device flow")
	}
}

func TestTokenSourcePersistsRefresh(t *testing.T) {
	m := newMockOP(t)
	ctx := context.Background()
	a, err := New(ctx, ProviderConfig{Issuer: m.issuer, ClientID: m.clientID, Audience: m.audience})
	if err != nil {
		t.Fatal(err)
	}
	// Seed with an already-expired access token so the source must refresh.
	seed := &Tokens{AccessToken: "stale", RefreshToken: "refresh-abc", Expiry: time.Now().Add(-time.Hour)}
	var saved *Tokens
	ts := a.TokenSource(ctx, seed, func(nt *Tokens) { saved = nt })

	tok, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "stale" {
		t.Error("expected a refreshed access token")
	}
	if saved == nil || saved.AccessToken != tok.AccessToken {
		t.Errorf("refresh was not persisted via save callback: %+v", saved)
	}
}
