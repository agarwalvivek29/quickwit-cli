// Package cli implements the `qw` command tree: context management, OIDC login,
// and the read-only log commands (search, tail, count, histogram, indexes,
// fields). Command wiring lives in root.go; this file holds the shared app
// state and the authenticated-client plumbing.
package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
	"github.com/agarwalvivek29/quickwit-cli/internal/qw"
)

// Build info, stamped from main via SetBuildInfo.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// SetBuildInfo records the build metadata for the User-Agent, `qw --version`,
// and `qw version`.
func SetBuildInfo(v, c, d string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
}

// App carries the resolved global flags and IO for a single invocation.
type App struct {
	ConfigPath      string
	ContextOverride string
	Output          string // table | json | raw
	NoColor         bool
	Fields          []string
	JQ              string // optional jq expression applied to JSON output
	Debug           bool   // trace HTTP requests to Err

	// Non-interactive auth overrides (also populated from QW_* env in root.go).
	Endpoint     string // overrides the context endpoint
	Token        string // static bearer token (skips OIDC)
	ClientSecret string // OIDC client-credentials secret (mint+refresh)

	Out io.Writer
	Err io.Writer
}

// loadConfig reads the config file (resolving the default path if unset).
func (a *App) loadConfig() (*config.Config, string, error) {
	path := a.ConfigPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

// resolveContext returns the selected context plus the loaded config and path.
// The override precedence is --context flag, then QW_CONTEXT, then
// current-context (the flag is pre-populated from the env in root.go).
func (a *App) resolveContext() (*config.Context, *config.Config, string, error) {
	cfg, path, err := a.loadConfig()
	if err != nil {
		return nil, nil, "", err
	}
	ctx, err := cfg.Resolve(a.ContextOverride)
	if err != nil {
		return nil, nil, "", err
	}
	return ctx, cfg, path, nil
}

// providerConfig builds the OIDC provider config from a context. secret is the
// client secret for a confidential client (empty for public/PKCE clients),
// sourced from --client-secret / QW_CLIENT_SECRET.
func providerConfig(c *config.Context, secret string) oidc.ProviderConfig {
	return oidc.ProviderConfig{
		Issuer:   c.OIDC.Issuer,
		ClientID: c.OIDC.ClientID,
		Secret:   secret,
		Audience: c.OIDC.Audience,
		Scopes:   c.OIDC.Scopes,
	}
}

// resolveEffectiveContext resolves the context for an authenticated command.
// It behaves like resolveContext, but when no context can be resolved it will
// synthesize an ephemeral one from the --endpoint/QW_ENDPOINT + QW_ISSUER/
// QW_CLIENT_ID/QW_AUDIENCE overrides — the "no config file at all" CI path.
func (a *App) resolveEffectiveContext() (*config.Context, *config.Config, string, error) {
	cfg, path, err := a.loadConfig()
	if err != nil {
		return nil, nil, "", err
	}
	cctx, rerr := cfg.Resolve(a.ContextOverride)
	if rerr != nil {
		if a.Endpoint == "" {
			return nil, nil, "", rerr
		}
		cctx = &config.Context{
			Name:     "(env)",
			Endpoint: a.Endpoint,
			OIDC: config.OIDCConfig{
				Issuer:   envOr(config.EnvIssuer),
				ClientID: envOr(config.EnvClientID),
				Audience: envOr(config.EnvAudience),
			},
		}
	}
	return cctx, cfg, path, nil
}

// authedClient builds a Quickwit client for the selected context whose HTTP
// transport injects the bearer token. The credential is resolved by
// tokenSource (static token, client-credentials, or cached login tokens).
func (a *App) authedClient(ctx context.Context) (*qw.Client, *config.Context, error) {
	cctx, cfg, path, err := a.resolveEffectiveContext()
	if err != nil {
		return nil, nil, err
	}

	ts, err := a.tokenSource(ctx, cctx, cfg, path)
	if err != nil {
		return nil, nil, err
	}

	hc := oauth2.NewClient(ctx, ts)
	// Insert the debug tracer beneath oauth2's auth transport so it sees the
	// final request (with the bearer attached, which it then redacts).
	if a.Debug {
		if ot, ok := hc.Transport.(*oauth2.Transport); ok {
			base := ot.Base
			if base == nil {
				base = http.DefaultTransport
			}
			ot.Base = &debugRT{base: base, w: a.Err}
		}
	}
	hc.Transport = &versionHeaderRT{base: hc.Transport}

	// --endpoint / QW_ENDPOINT overrides the context's endpoint for this call
	// without rewriting the config file.
	endpoint := cctx.Endpoint
	if a.Endpoint != "" {
		endpoint = a.Endpoint
	}

	client := qw.New(endpoint, qw.WithHTTPClient(hc), qw.WithUserAgent("qw/"+version))
	return client, cctx, nil
}

// tokenSource picks the credential for cctx, in precedence order:
//  1. static bearer token   (--token / QW_TOKEN)
//  2. client-credentials    (--client-secret / QW_CLIENT_SECRET)
//  3. cached login tokens   (from `qw login`), auto-refreshed + persisted
func (a *App) tokenSource(ctx context.Context, cctx *config.Context, cfg *config.Config, path string) (oauth2.TokenSource, error) {
	switch {
	case a.Token != "":
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: a.Token, TokenType: "Bearer"}), nil

	case a.ClientSecret != "":
		if cctx.OIDC.Issuer == "" || cctx.OIDC.ClientID == "" {
			return nil, fmt.Errorf("client-credentials auth needs an issuer and client-id " +
				"(set them on the context, or via QW_ISSUER / QW_CLIENT_ID)")
		}
		auth, err := oidc.New(ctx, providerConfig(cctx, a.ClientSecret))
		if err != nil {
			return nil, err
		}
		return auth.ClientCredentialsTokenSource(ctx, a.ClientSecret), nil

	default:
		if cctx.Auth == nil || cctx.Auth.AccessToken == "" {
			return nil, fmt.Errorf("not logged in for context %q: run `qw login` "+
				"(or set QW_TOKEN / QW_CLIENT_SECRET for non-interactive auth)", cctx.Name)
		}
		auth, err := oidc.New(ctx, providerConfig(cctx, a.ClientSecret))
		if err != nil {
			return nil, err
		}
		prev := &oidc.Tokens{
			AccessToken:  cctx.Auth.AccessToken,
			RefreshToken: cctx.Auth.RefreshToken,
			IDToken:      cctx.Auth.IDToken,
			TokenType:    cctx.Auth.TokenType,
			Expiry:       cctx.Auth.Expiry,
		}
		save := func(nt *oidc.Tokens) {
			cctx.Auth = tokensToConfig(nt)
			// Best-effort persistence of refreshed tokens; a failure here must
			// not break the command in flight.
			_ = config.Save(path, cfg)
		}
		return auth.TokenSource(ctx, prev, save), nil
	}
}

func tokensToConfig(t *oidc.Tokens) *config.AuthTokens {
	return &config.AuthTokens{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		IDToken:      t.IDToken,
		TokenType:    t.TokenType,
		Expiry:       t.Expiry,
	}
}

// versionHeaderRT stamps the CLI version onto every request so the proxy can
// record it in the audit trail.
type versionHeaderRT struct{ base http.RoundTripper }

func (rt *versionHeaderRT) RoundTrip(r *http.Request) (*http.Response, error) {
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	r2 := r.Clone(r.Context())
	r2.Header.Set("X-Qw-Cli-Version", version)
	return base.RoundTrip(r2)
}

// debugRT logs each request line and response status/latency to w, redacting
// the bearer token. Enabled by --debug / -v; helps diagnose proxy/OIDC issues.
type debugRT struct {
	base http.RoundTripper
	w    io.Writer
}

func (rt *debugRT) RoundTrip(r *http.Request) (*http.Response, error) {
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	fmt.Fprintf(rt.w, "> %s %s\n", r.Method, r.URL)
	if r.Header.Get("Authorization") != "" {
		fmt.Fprintln(rt.w, "> authorization: Bearer [redacted]")
	}
	start := time.Now()
	resp, err := base.RoundTrip(r)
	dur := time.Since(start).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(rt.w, "< error after %s: %v\n", dur, err)
		return resp, err
	}
	fmt.Fprintf(rt.w, "< %d %s (%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode), dur)
	return resp, err
}

// envOr returns the value of environment variable key (empty string if unset).
func envOr(key string) string { return os.Getenv(key) }
