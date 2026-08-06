package audit

import (
	"testing"
	"time"
)

func TestPoolConfigDefaults(t *testing.T) {
	got := PoolConfig{}.withDefaults()
	want := PoolConfig{
		MaxConns:          4,
		MinConns:          0,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: time.Minute,
	}
	if got != want {
		t.Errorf("withDefaults() = %+v, want %+v", got, want)
	}
}

func TestPoolConfigKeepsExplicitValues(t *testing.T) {
	in := PoolConfig{
		MaxConns:          16,
		MinConns:          2,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   time.Minute,
		HealthCheckPeriod: 15 * time.Second,
	}
	if got := in.withDefaults(); got != in {
		t.Errorf("withDefaults() overrode explicit values: got %+v, want %+v", got, in)
	}
}

// NewPGXSink must reject an unparseable DSN before it ever dials Postgres.
func TestNewPGXSinkRejectsBadDSN(t *testing.T) {
	if _, err := NewPGXSink(t.Context(), "://not a dsn", PoolConfig{}); err == nil {
		t.Fatal("expected error for malformed DSN, got nil")
	}
}
