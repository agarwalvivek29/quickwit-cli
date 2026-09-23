package apikey

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewPGXStoreRejectsBadDSN(t *testing.T) {
	if _, err := NewPGXStore(t.Context(), "://not a dsn"); err == nil {
		t.Fatal("expected error for malformed DSN, got nil")
	}
}

func TestGenerateKeyFormat(t *testing.T) {
	re := regexp.MustCompile(`^qw_pat_[0-9a-f]{64}$`)
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		k, err := generateKey()
		if err != nil {
			t.Fatalf("generateKey: %v", err)
		}
		if !strings.HasPrefix(k, KeyPrefix) {
			t.Fatalf("key %q missing prefix %q", k, KeyPrefix)
		}
		if !re.MatchString(k) {
			t.Fatalf("key %q does not match expected format", k)
		}
		if seen[k] {
			t.Fatalf("generateKey produced a duplicate: %q", k)
		}
		seen[k] = true
		// The stored display prefix must never reveal the full secret.
		if len(k[:prefixDisplayLen]) >= len(k) {
			t.Fatalf("display prefix is not shorter than the key")
		}
	}
}

func TestHashKeyDeterministicAndHex(t *testing.T) {
	k := "qw_pat_abc"
	h1, h2 := hashKey(k), hashKey(k)
	if h1 != h2 {
		t.Fatalf("hashKey not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("hashKey len = %d, want 64", len(h1))
	}
	if hashKey("qw_pat_abd") == h1 {
		t.Fatal("distinct keys hashed to the same value")
	}
	if strings.Contains(h1, k) {
		t.Fatal("hash contains the raw key")
	}
}
