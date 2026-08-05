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

	"golang.org/x/oauth2"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
	"github.com/agarwalvivek29/quickwit-cli/internal/qw"
)

// version is stamped from main via SetVersion.
var version = "dev"

// SetVersion records the build version for the User-Agent and `qw --version`.
func SetVersion(v string) {
	if v != "" {
		version = v
	}
}

// App carries the resolved global flags and IO for a single invocation.
type App struct {
	ConfigPath      string
	ContextOverride string
	Output          string // table | json | raw
	NoColor         bool
	Fields          []string

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

// providerConfig builds the OIDC provider config from a context.
func providerConfig(c *config.Context) oidc.ProviderConfig {
	return oidc.ProviderConfig{
		Issuer:   c.OIDC.Issuer,
		ClientID: c.OIDC.ClientID,
		Audience: c.OIDC.Audience,
		Scopes:   c.OIDC.Scopes,
	}
}

// authedClient builds a Quickwit client for the selected context whose HTTP
// transport injects (and refreshes) the OIDC bearer token, persisting any
// refreshed tokens back to the config file.
func (a *App) authedClient(ctx context.Context) (*qw.Client, *config.Context, error) {
	cctx, cfg, path, err := a.resolveContext()
	if err != nil {
		return nil, nil, err
	}
	if cctx.Auth == nil || cctx.Auth.AccessToken == "" {
		return nil, nil, fmt.Errorf("not logged in for context %q: run `qw login`", cctx.Name)
	}

	auth, err := oidc.New(ctx, providerConfig(cctx))
	if err != nil {
		return nil, nil, err
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
		// Best-effort persistence of refreshed tokens; a failure here must not
		// break the command in flight.
		_ = config.Save(path, cfg)
	}
	ts := auth.TokenSource(ctx, prev, save)

	hc := oauth2.NewClient(ctx, ts)
	hc.Transport = &versionHeaderRT{base: hc.Transport}

	client := qw.New(cctx.Endpoint, qw.WithHTTPClient(hc), qw.WithUserAgent("qw/"+version))
	return client, cctx, nil
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
