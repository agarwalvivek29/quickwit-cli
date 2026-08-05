package timeparse

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"15m", 15 * time.Minute, false},
		{"1h", time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"2d", 48 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"1w3d", 10 * 24 * time.Hour, false},
		{"-15m", 15 * time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"", 0, true},
		{"15", 0, true},
		{"15x", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseDuration(tt.in)
		if tt.err {
			if err == nil {
				t.Errorf("ParseDuration(%q) = %v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDuration(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSince(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	got, err := Since("15m", now)
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(-15 * time.Minute).Unix()
	if got != want {
		t.Errorf("Since(15m) = %d, want %d", got, want)
	}
}

func TestAbsolute(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want int64
		err  bool
	}{
		{"now", now.Unix(), false},
		{"2h", now.Add(-2 * time.Hour).Unix(), false},
		{"1754481600", 1754481600, false},           // epoch seconds
		{"1754481600000", 1754481600, false},        // epoch millis -> seconds
		{"2026-08-06T12:00:00Z", now.Unix(), false}, // RFC3339
		{"2026-08-06", time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC).Unix(), false},
		{"2026-08-06 12:00:00", now.Unix(), false},
		{"garbage", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := Absolute(tt.in, now)
		if tt.err {
			if err == nil {
				t.Errorf("Absolute(%q) = %d, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Absolute(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Absolute(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
