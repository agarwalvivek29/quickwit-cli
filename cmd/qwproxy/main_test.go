package main

import "testing"

func TestConfigValidateFailsClosed(t *testing.T) {
	// No audience and no explicit opt-in → refuse to start (the fail-open hole).
	if err := (config{}).validate(); err == nil {
		t.Error("validate() must reject an empty audience with no insecure opt-in")
	}

	// A client id is enough to start, and it is the enforced audience.
	c := config{oidcClientID: "qw-prod"}
	if err := c.validate(); err != nil {
		t.Errorf("validate() with a client id: %v", err)
	}
	if c.expectedAudience() != "qw-prod" {
		t.Errorf("expectedAudience() = %q, want qw-prod", c.expectedAudience())
	}

	// Legacy QWPROXY_OIDC_AUDIENCE still satisfies the check.
	if err := (config{oidcAudience: "quickwit-api"}).validate(); err != nil {
		t.Errorf("validate() with legacy audience: %v", err)
	}

	// Client id takes precedence over the legacy audience.
	if got := (config{oidcClientID: "cid", oidcAudience: "aud"}).expectedAudience(); got != "cid" {
		t.Errorf("expectedAudience() = %q, want client id to win", got)
	}

	// Explicit insecure opt-in → allowed to start with no audience.
	if err := (config{insecureSkipAudience: true}).validate(); err != nil {
		t.Errorf("insecure opt-in should permit an empty audience: %v", err)
	}
}
