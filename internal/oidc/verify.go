package oidc

import (
	"context"
	"fmt"

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

// NewVerifier performs discovery for issuer and returns a Verifier. If audience
// is non-empty it is enforced as the expected "aud"; otherwise the audience
// check is skipped (signature + issuer + expiry are always enforced).
func NewVerifier(ctx context.Context, issuer, audience string) (*Verifier, error) {
	provider, err := coreoidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", issuer, err)
	}
	cfg := &coreoidc.Config{ClientID: audience}
	if audience == "" {
		cfg.SkipClientIDCheck = true
	}
	return &Verifier{verifier: provider.Verifier(cfg)}, nil
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
