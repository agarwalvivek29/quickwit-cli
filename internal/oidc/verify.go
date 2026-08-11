package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

// Verifier validates incoming access tokens on the proxy side. It is stateless
// per request: signature is checked against the provider's JWKS (fetched once
// and cached + rotated by go-oidc), and issuer/expiry/audience are enforced.
type Verifier struct {
	verifier *coreoidc.IDTokenVerifier
}

// Claims are the identity fields the proxy records for the audit trail.
type Claims struct {
	Subject           string
	Email             string
	PreferredUsername string
}

// Options overrides how the proxy reaches the identity provider. The zero value
// reproduces plain OIDC discovery against the issuer, so existing callers are
// unaffected.
//
// These exist for isolated networks with no direct internet egress, where the
// token issuer host is NOT directly reachable and OIDC discovery + JWKS are only
// available through an internal gateway (a reverse proxy). In that setup the
// access token's `iss` claim still carries the real issuer (the IdP stamps it
// and it is immutable), so the verifier must expect that exact value while
// fetching the metadata + signing keys from the gateway instead.
type Options struct {
	// DiscoveryURL, when set, is the base the discovery document is fetched from
	// (<DiscoveryURL>/.well-known/openid-configuration) instead of
	// <issuer>/.well-known/openid-configuration. The document's own `issuer` is
	// still honored for the token `iss` check, so `issuer` may be left empty to
	// adopt whatever the document advertises — handy when the real issuer host
	// must not appear in config at all.
	DiscoveryURL string
	// JWKSURL, when set, overrides the signing-key endpoint (normally the
	// discovery document's absolute jwks_uri). Use it when that jwks_uri points
	// at a host the proxy can't reach and the keys are served via the gateway.
	JWKSURL string
}

// NewVerifier returns a Verifier for issuer. If audience is non-empty it is
// enforced as the expected "aud"; otherwise the audience check is skipped
// (signature + issuer + expiry are always enforced).
//
// With the zero Options it performs standard discovery against issuer. Set
// opts.DiscoveryURL / opts.JWKSURL for gateway-only networks (see Options).
func NewVerifier(ctx context.Context, issuer, audience string, opts Options) (*Verifier, error) {
	cfg := &coreoidc.Config{ClientID: audience}
	if audience == "" {
		cfg.SkipClientIDCheck = true
	}

	// Explicit JWKS override: skip go-oidc discovery entirely. qwproxy is a
	// resource server (it only validates bearer tokens), so it needs just the
	// expected issuer string + the signing keys — never the token/authorize
	// endpoints. This is the path for gateway-only networks where the discovery
	// document's absolute jwks_uri is unreachable.
	if opts.JWKSURL != "" {
		expected := issuer
		if expected == "" {
			if opts.DiscoveryURL == "" {
				return nil, fmt.Errorf("oidc: issuer or discoveryURL is required when jwksURL is set")
			}
			iss, err := discoverIssuer(ctx, opts.DiscoveryURL)
			if err != nil {
				return nil, err
			}
			expected = iss
		}
		ks := coreoidc.NewRemoteKeySet(ctx, opts.JWKSURL)
		return &Verifier{verifier: coreoidc.NewVerifier(expected, ks, cfg)}, nil
	}

	// Discovery path. When DiscoveryURL differs from the issuer, fetch discovery
	// there but keep `issuer` as the trusted issuer — go-oidc otherwise rejects a
	// discovery document whose `issuer` != the URL it was fetched from.
	discoURL := issuer
	if opts.DiscoveryURL != "" {
		discoURL = opts.DiscoveryURL
		if issuer != "" {
			ctx = coreoidc.InsecureIssuerURLContext(ctx, issuer)
		}
	}
	if discoURL == "" {
		return nil, fmt.Errorf("oidc: issuer or discoveryURL is required")
	}
	provider, err := coreoidc.NewProvider(ctx, discoURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", discoURL, err)
	}
	return &Verifier{verifier: provider.Verifier(cfg)}, nil
}

// discoverIssuer fetches only the `issuer` field from the OIDC discovery
// document served under base (base + /.well-known/openid-configuration). Used to
// adopt the IdP's advertised issuer without naming it in config.
func discoverIssuer(ctx context.Context, base string) (string, error) {
	u := strings.TrimRight(base, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery fetch %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery %s: status %d", u, resp.StatusCode)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("oidc discovery decode %s: %w", u, err)
	}
	if doc.Issuer == "" {
		return "", fmt.Errorf("oidc discovery %s: document has no issuer", u)
	}
	return doc.Issuer, nil
}

// Verify checks a raw bearer token and returns its identity claims, or an error
// if the token is invalid, expired, from the wrong issuer, or for the wrong
// audience.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	tok, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	var extra struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	_ = tok.Claims(&extra)
	return &Claims{
		Subject:           tok.Subject,
		Email:             extra.Email,
		PreferredUsername: extra.PreferredUsername,
	}, nil
}
