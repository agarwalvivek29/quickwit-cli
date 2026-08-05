package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGetPath(t *testing.T) {
	doc := parseDoc(json.RawMessage(`{"a":{"b":"deep"},"n":42,"f":1.5,"ok":true}`))
	cases := map[string]string{
		"a.b": "deep",
		"n":   "42",
		"f":   "1.5",
		"ok":  "true",
	}
	for path, want := range cases {
		got, ok := getPath(doc, path)
		if !ok || got != want {
			t.Errorf("getPath(%q) = %q,%v want %q", path, got, ok, want)
		}
	}
	if _, ok := getPath(doc, "a.missing"); ok {
		t.Error("expected miss for a.missing")
	}
}

func TestAutoColumns(t *testing.T) {
	doc := parseDoc(json.RawMessage(`{"timestamp":"t","level":"INFO","service":"svc","message":"hi","extra":1}`))
	cols := autoColumns(doc)
	want := []string{"timestamp", "level", "service", "message"}
	if strings.Join(cols, ",") != strings.Join(want, ",") {
		t.Errorf("autoColumns = %v, want %v", cols, want)
	}
}

func TestColorizeLevel(t *testing.T) {
	if got := colorizeLevel("ERROR", false); got != "ERROR" {
		t.Errorf("disabled color changed value: %q", got)
	}
	if got := colorizeLevel("ERROR", true); !strings.Contains(got, ansiRed) || !strings.HasSuffix(got, ansiReset) {
		t.Errorf("ERROR not red: %q", got)
	}
	if got := colorizeLevel("NOTALEVEL", true); got != "NOTALEVEL" {
		t.Errorf("unknown level should be unchanged: %q", got)
	}
}

func TestRenderRawUsesMessage(t *testing.T) {
	var out strings.Builder
	a := &App{Out: &out, Err: &out, Output: outRaw}
	err := a.renderHits([]json.RawMessage{json.RawMessage(`{"message":"hello","level":"INFO"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "hello" {
		t.Errorf("raw output = %q, want hello", out.String())
	}
}

func TestRenderRawWithFieldsProjection(t *testing.T) {
	var out strings.Builder
	a := &App{Out: &out, Err: &out, Output: outRaw, Fields: []string{"level", "message"}}
	err := a.renderHits([]json.RawMessage{json.RawMessage(`{"message":"boom","level":"ERROR"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "ERROR boom" {
		t.Errorf("projected output = %q, want 'ERROR boom'", out.String())
	}
}
