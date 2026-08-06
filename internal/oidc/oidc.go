// Package oidc implements both halves of the auth story:
//
//   - CLI side: interactive login via OAuth 2.0 Authorization Code + PKCE over a
//     loopback redirect, with a Device Authorization Grant fallback for headless
//     hosts; plus a refreshing, self-persisting token source.
//   - Proxy side (verify.go): stateless JWT validation against the provider's
//     JWKS.
//
// The same code targets Keycloak (local sim) and Okta (prod) — only the issuer
// URL differs. Nothing here holds a client secret: the CLI is a public client
// and PKCE is what proves possession of the authorization request.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// randomState returns an unguessable OAuth state value for CSRF protection.
func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// defaultScopes requests an OIDC session (openid), user claims (profile/email)
// for the audit identity, and offline_access so the provider returns a refresh
// token.
var defaultScopes = []string{coreoidc.ScopeOpenID, "profile", "email", coreoidc.ScopeOfflineAccess}

// ProviderConfig is the per-context identity config.
type ProviderConfig struct {
	Issuer   string
	ClientID string
	Audience string   // optional; requested so the access token's aud matches the API
	Scopes   []string // optional; defaults to defaultScopes
}

// Tokens is the result of a successful login.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Expiry       time.Time
}

// DevicePrompt is handed to the caller during a device-grant login so it can
// tell the user where to go and what code to enter.
type DevicePrompt struct {
	VerificationURI         string
	VerificationURIComplete string
	UserCode                string
	ExpiresIn               time.Duration
}

// Authenticator drives the login flows for one provider. Construct with New,
// which performs OIDC discovery.
type Authenticator struct {
	pc       ProviderConfig
	conf     *oauth2.Config
	provider *coreoidc.Provider

	// Opener launches the system browser at url; overridable in tests.
	Opener func(url string) error
	// BindAddr is the loopback listen address for the PKCE redirect.
	BindAddr string
}

// New performs OIDC discovery for pc.Issuer and returns a ready Authenticator.
func New(ctx context.Context, pc ProviderConfig) (*Authenticator, error) {
	provider, err := coreoidc.NewProvider(ctx, pc.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", pc.Issuer, err)
	}
	scopes := pc.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	ep := provider.Endpoint()
	// The device authorization endpoint is not part of the standard oauth2
	// endpoint that go-oidc surfaces, so pull it from the raw discovery doc.
	var disco struct {
		DeviceAuthURL string `json:"device_authorization_endpoint"`
	}
	_ = provider.Claims(&disco)
	ep.DeviceAuthURL = disco.DeviceAuthURL

	conf := &oauth2.Config{
		ClientID: pc.ClientID,
		Endpoint: ep,
		Scopes:   scopes,
	}
	return &Authenticator{
		pc:       pc,
		conf:     conf,
		provider: provider,
		Opener:   openBrowser,
		BindAddr: "127.0.0.1:0",
	}, nil
}

// audienceParam requests the API audience where the provider supports it
// (Auth0/Okta custom authorization servers use the "audience" param).
func (a *Authenticator) audienceParam() []oauth2.AuthCodeOption {
	if a.pc.Audience == "" {
		return nil
	}
	return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("audience", a.pc.Audience)}
}

// Login runs the Authorization Code + PKCE flow over a loopback redirect: it
// binds an ephemeral 127.0.0.1 port, opens the browser to the provider, and
// exchanges the returned code (bound by the PKCE verifier) for tokens.
func (a *Authenticator) Login(ctx context.Context) (*Tokens, error) {
	ln, err := net.Listen("tcp", a.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind loopback listener: %w", err)
	}
	defer func() { _ = ln.Close() }()

	redirectURL := fmt.Sprintf("http://%s/callback", ln.Addr().String())
	conf := *a.conf // copy so RedirectURL is per-login
	conf.RedirectURL = redirectURL

	verifier := oauth2.GenerateVerifier()
	state, err := randomState()
	if err != nil {
		return nil, err
	}

	opts := append([]oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	}, a.audienceParam()...)
	authURL := conf.AuthCodeURL(state, opts...)

	type result struct {
		code string
		err  error
	}
	resCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "login failed: "+e, http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("authorization error: %s %s", e, q.Get("error_description"))}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- result{err: errors.New("state mismatch (possible CSRF)")}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(successHTML))
		resCh <- result{code: q.Get("code")}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := a.Opener(authURL); err != nil {
		// Not fatal: the user can copy the URL from the message the caller prints.
		_ = err
	}

	var code string
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		code = res.code
	}

	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	return tokensFrom(tok), nil
}

// LoginDevice runs the Device Authorization Grant: it asks the provider for a
// device+user code, invokes prompt so the caller can display them, then polls
// the token endpoint until the user approves (or the code expires).
func (a *Authenticator) LoginDevice(ctx context.Context, prompt func(DevicePrompt)) (*Tokens, error) {
	if a.conf.Endpoint.DeviceAuthURL == "" {
		return nil, errors.New("provider does not advertise a device authorization endpoint")
	}
	opts := append([]oauth2.AuthCodeOption{}, a.audienceParam()...)
	da, err := a.conf.DeviceAuth(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	if prompt != nil {
		prompt(DevicePrompt{
			VerificationURI:         da.VerificationURI,
			VerificationURIComplete: da.VerificationURIComplete,
			UserCode:                da.UserCode,
			ExpiresIn:               time.Until(da.Expiry),
		})
	}
	tok, err := a.conf.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, fmt.Errorf("device token poll: %w", err)
	}
	return tokensFrom(tok), nil
}

// ClientCredentialsTokenSource returns an auto-refreshing token source that
// mints access tokens via the OAuth 2.0 client-credentials grant — the
// machine-to-machine flow for CI/cron, where there is no user and no browser.
// The provider's OIDC client must be confidential and have this grant enabled.
// Unlike the interactive flows this one does hold a secret, so callers should
// source it from the environment (QW_CLIENT_SECRET), not a flag.
func (a *Authenticator) ClientCredentialsTokenSource(ctx context.Context, clientSecret string) oauth2.TokenSource {
	cc := &clientcredentials.Config{
		ClientID:     a.pc.ClientID,
		ClientSecret: clientSecret,
		TokenURL:     a.conf.Endpoint.TokenURL,
		AuthStyle:    oauth2.AuthStyleAutoDetect,
	}
	if len(a.pc.Scopes) > 0 {
		cc.Scopes = a.pc.Scopes
	}
	// Auth0/Okta custom authorization servers select the API by "audience".
	if a.pc.Audience != "" {
		cc.EndpointParams = url.Values{"audience": {a.pc.Audience}}
	}
	return cc.TokenSource(ctx)
}

// TokenSource returns an auto-refreshing token source seeded from prev. When a
// refresh yields a new access token, save is invoked so the caller can persist
// it back to the context file. save may be nil.
func (a *Authenticator) TokenSource(ctx context.Context, prev *Tokens, save func(*Tokens)) oauth2.TokenSource {
	base := a.conf.TokenSource(ctx, prev.oauth2Token())
	return &persistingSource{base: base, last: prev.AccessToken, save: save}
}

type persistingSource struct {
	base oauth2.TokenSource
	last string
	save func(*Tokens)
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	tok, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	if tok.AccessToken != p.last {
		p.last = tok.AccessToken
		if p.save != nil {
			p.save(tokensFrom(tok))
		}
	}
	return tok, nil
}

func tokensFrom(tok *oauth2.Token) *Tokens {
	t := &Tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
	}
	if id, ok := tok.Extra("id_token").(string); ok {
		t.IDToken = id
	}
	return t
}

func (t *Tokens) oauth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Expiry:       t.Expiry,
	}
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}

const successHTML = `<!doctype html><html><head><meta charset="utf-8"><title>qw</title></head>
<body style="font-family:system-ui;text-align:center;padding-top:4rem">
<h2>You're signed in.</h2><p>You can close this tab and return to the terminal.</p></body></html>`
