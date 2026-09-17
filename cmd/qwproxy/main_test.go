package main

import "testing"

func TestConfigValidateFailsClosed(t *testing.T) {
	// No audience and no explicit opt-in → refuse to start (the fail-open hole).
	if err := (config{}).validate(); err == nil {
		t.Error("validate() must reject an empty audience with no insecure opt-in")
	}

	// A client id is enough to start, and it is an enforced audience.
	c := config{oidcClientID: "qw-prod"}
	if err := c.validate(); err != nil {
		t.Errorf("validate() with a client id: %v", err)
	}
	if got := c.expectedAudiences(); len(got) != 1 || got[0] != "qw-prod" {
		t.Errorf("expectedAudiences() = %v, want [qw-prod]", got)
	}

	// Legacy QWPROXY_OIDC_AUDIENCE still satisfies the check.
	if err := (config{oidcAudience: "quickwit-api"}).validate(); err != nil {
		t.Errorf("validate() with legacy audience: %v", err)
	}

	// Multi-audience: client id, extra client ids, and the legacy audience are
	// all accepted, client id first, de-duplicated.
	got := config{oidcClientID: "cid", oidcClientIDs: []string{"grafana", "cid"}, oidcAudience: "aud"}.expectedAudiences()
	want := []string{"cid", "grafana", "aud"}
	if len(got) != len(want) {
		t.Fatalf("expectedAudiences() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expectedAudiences()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Explicit insecure opt-in → allowed to start with no audience.
	if err := (config{insecureSkipAudience: true}).validate(); err != nil {
		t.Errorf("insecure opt-in should permit an empty audience: %v", err)
	}
}
