// Package timeparse turns the human time expressions a log CLI accepts
// (--since 15m, --from 2d, --to now, RFC3339, epoch) into unix epoch seconds,
// which is what Quickwit's start_timestamp / end_timestamp fields expect.
//
// It is a Go port of the quickwit-mcp timeparse helper, extended with the
// calendar units (d, w) that Go's time.ParseDuration does not support.
package timeparse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// durRe matches one or more <number><unit> chunks, e.g. "1w2d3h30m".
var durRe = regexp.MustCompile(`^(\d+)(w|d|h|m|s)`)

var unitDur = map[string]time.Duration{
	"s": time.Second,
	"m": time.Minute,
	"h": time.Hour,
	"d": 24 * time.Hour,
	"w": 7 * 24 * time.Hour,
}

// ParseDuration parses a relative duration supporting weeks and days on top of
// the standard s/m/h units, e.g. "15m", "1h30m", "2d", "1w3d". A leading "-" is
// allowed and ignored (both "15m" and "-15m" mean the same span).
func ParseDuration(s string) (time.Duration, error) {
	orig := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return 0, fmt.Errorf("empty duration %q", orig)
	}
	var total time.Duration
	for s != "" {
		m := durRe.FindStringSubmatch(s)
		if m == nil {
			return 0, fmt.Errorf("invalid duration %q: unexpected %q", orig, s)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", orig, err)
		}
		total += time.Duration(n) * unitDur[m[2]]
		s = s[len(m[0]):]
	}
	return total, nil
}

// Since returns the epoch-seconds instant that is ParseDuration(s) before now,
// i.e. the start bound for "--since 15m".
func Since(s string, now time.Time) (int64, error) {
	d, err := ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return now.Add(-d).Unix(), nil
}

// Absolute parses a --from/--to value into epoch seconds. Accepted forms:
//   - "now"                        -> now
//   - a relative duration ("2d")   -> now - duration (i.e. "ago")
//   - unix seconds  (10 digits)    -> as-is
//   - unix millis   (13 digits)    -> /1000
//   - RFC3339 ("2006-01-02T15:04:05Z")
//   - "2006-01-02 15:04:05" (UTC)
//   - "2006-01-02"          (UTC midnight)
func Absolute(s string, now time.Time) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty time")
	}
	if strings.EqualFold(s, "now") {
		return now.Unix(), nil
	}

	// Pure digits: epoch seconds or millis.
	if isDigits(s) {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid epoch %q: %w", s, err)
		}
		if len(s) >= 13 {
			return n / 1000, nil
		}
		return n, nil
	}

	// Relative duration -> "ago".
	if d, err := ParseDuration(s); err == nil {
		return now.Add(-d).Unix(), nil
	}

	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix(), nil
		}
	}
	return 0, fmt.Errorf("unrecognized time %q (want now, a duration like 15m, epoch, RFC3339, or YYYY-MM-DD)", s)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
