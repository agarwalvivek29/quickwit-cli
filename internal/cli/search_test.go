package cli

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/qw"
)

func TestIndexQuery(t *testing.T) {
	if i, q, err := indexQuery("", []string{"idx", "level:ERROR"}); err != nil || i != "idx" || q != "level:ERROR" {
		t.Errorf("two-arg = %q,%q,%v", i, q, err)
	}
	if i, q, err := indexQuery("def", []string{"level:ERROR"}); err != nil || i != "def" || q != "level:ERROR" {
		t.Errorf("default-index = %q,%q,%v", i, q, err)
	}
	if _, _, err := indexQuery("", []string{"level:ERROR"}); err == nil {
		t.Error("expected error when no index and no default")
	}
}

func TestTimeFlagsResolve(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	// Empty -> default 15m window.
	tf := &timeFlags{}
	start, end, err := tf.resolve(now)
	if err != nil || start == nil || *start != now.Add(-15*time.Minute).Unix() {
		t.Errorf("default window: start=%v end=%v err=%v", start, end, err)
	}

	// Explicit since.
	tf = &timeFlags{since: "1h"}
	start, _, _ = tf.resolve(now)
	if *start != now.Add(-time.Hour).Unix() {
		t.Errorf("since 1h start = %d", *start)
	}

	// from/to.
	tf = &timeFlags{from: "2026-08-06", to: "now"}
	start, end, err = tf.resolve(now)
	if err != nil || start == nil || end == nil || *end != now.Unix() {
		t.Errorf("from/to: start=%v end=%v err=%v", start, end, err)
	}

	// bad value.
	tf = &timeFlags{from: "garbage"}
	if _, _, err := tf.resolve(now); err == nil {
		t.Error("expected error for bad --from")
	}
}

func TestFlattenFields(t *testing.T) {
	fms := []qw.FieldMapping{
		{Name: "message", Type: "text"},
		{Name: "k8s", Type: "object", FieldMappings: []qw.FieldMapping{
			{Name: "pod", Type: "text"},
			{Name: "ns", Type: "text"},
		}},
	}
	rows := flattenFields("", fms)
	got := map[string]string{}
	for _, r := range rows {
		got[r[0]] = r[1]
	}
	if got["message"] != "text" || got["k8s.pod"] != "text" || got["k8s.ns"] != "text" {
		t.Errorf("flattenFields = %v", got)
	}
	if len(rows) != 3 {
		t.Errorf("expected 3 leaf fields, got %d", len(rows))
	}
}

func TestParseHitTS(t *testing.T) {
	if got := parseHitTS(json.RawMessage(`{"ts":"2026-08-06T12:00:00Z"}`), "ts"); got != time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("rfc3339 ts = %d", got)
	}
	if got := parseHitTS(json.RawMessage(`{"ts":1754481600}`), "ts"); got != 1754481600 {
		t.Errorf("epoch s ts = %d", got)
	}
	if got := parseHitTS(json.RawMessage(`{"ts":1754481600000}`), "ts"); got != 1754481600 {
		t.Errorf("epoch ms ts = %d", got)
	}
	if got := parseHitTS(json.RawMessage(`{"other":1}`), "ts"); got != 0 {
		t.Errorf("missing ts = %d, want 0", got)
	}
}

func TestBar(t *testing.T) {
	if got := bar(5, 10, 10); got != "#####" {
		t.Errorf("bar = %q", got)
	}
	if got := bar(0, 0, 10); got != "" {
		t.Errorf("bar zero-max = %q", got)
	}
}

func TestChronologicalSorts(t *testing.T) {
	hits := []json.RawMessage{
		json.RawMessage(`{"ts":300}`),
		json.RawMessage(`{"ts":100}`),
		json.RawMessage(`{"ts":200}`),
	}
	got := chronological(hits, "ts")
	if got[0].ts != 100 || got[1].ts != 200 || got[2].ts != 300 {
		t.Errorf("not sorted ascending: %v %v %v", got[0].ts, got[1].ts, got[2].ts)
	}
}
