package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

// Output formats.
const (
	outTable = "table"
	outJSON  = "json"
	outRaw   = "raw"
)

// candidate field names for auto-detected table columns, in priority order.
var (
	tsFields      = []string{"timestamp", "ts", "@timestamp", "time", "datetime"}
	levelFields   = []string{"level", "severity", "lvl", "loglevel"}
	serviceFields = []string{"service", "service_name", "app", "logger"}
	msgFields     = []string{"message", "msg", "body", "log", "event"}
)

// renderHits writes hits in the app's chosen output format.
func (a *App) renderHits(hits []json.RawMessage) error {
	switch a.Output {
	case outJSON:
		return a.renderJSON(hits)
	case outRaw:
		return a.renderRaw(hits)
	default:
		return a.renderTable(hits)
	}
}

func (a *App) renderJSON(hits []json.RawMessage) error {
	docs := make([]json.RawMessage, len(hits))
	copy(docs, hits)
	enc := json.NewEncoder(a.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(docs)
}

func (a *App) renderRaw(hits []json.RawMessage) error {
	for _, h := range hits {
		doc := parseDoc(h)
		if len(a.Fields) > 0 {
			parts := make([]string, 0, len(a.Fields))
			for _, f := range a.Fields {
				v, _ := getPath(doc, f)
				parts = append(parts, v)
			}
			fmt.Fprintln(a.Out, strings.Join(parts, " "))
			continue
		}
		if msg, ok := firstPresent(doc, msgFields); ok {
			fmt.Fprintln(a.Out, msg)
		} else {
			fmt.Fprintln(a.Out, string(h))
		}
	}
	return nil
}

func (a *App) renderTable(hits []json.RawMessage) error {
	if len(hits) == 0 {
		fmt.Fprintln(a.Err, "no hits")
		return nil
	}
	docs := make([]map[string]any, len(hits))
	for i, h := range hits {
		docs[i] = parseDoc(h)
	}

	cols := a.Fields
	if len(cols) == 0 {
		cols = autoColumns(docs[0])
	}
	if len(cols) == 0 {
		// No recognizable columns — fall back to compact JSON lines.
		for _, h := range hits {
			fmt.Fprintln(a.Out, string(h))
		}
		return nil
	}

	color := a.colorEnabled()
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(upper(cols), "\t"))
	for _, doc := range docs {
		cells := make([]string, len(cols))
		for i, c := range cols {
			v, _ := getPath(doc, c)
			if isLevelColumn(c) {
				v = colorizeLevel(v, color)
			}
			cells[i] = v
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}

// autoColumns picks a sensible default column set from the fields present.
func autoColumns(doc map[string]any) []string {
	var cols []string
	for _, group := range [][]string{tsFields, levelFields, serviceFields, msgFields} {
		if name, ok := firstKey(doc, group); ok {
			cols = append(cols, name)
		}
	}
	return cols
}

// getPath resolves a dot-path (e.g. "kubernetes.pod") into a scalar string.
func getPath(doc map[string]any, path string) (string, bool) {
	parts := strings.Split(path, ".")
	var cur any = doc
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = m[p]
		if !ok {
			return "", false
		}
	}
	return stringify(cur), true
}

func firstPresent(doc map[string]any, keys []string) (string, bool) {
	if name, ok := firstKey(doc, keys); ok {
		return stringify(doc[name]), true
	}
	return "", false
}

func firstKey(doc map[string]any, keys []string) (string, bool) {
	for _, k := range keys {
		if _, ok := doc[k]; ok {
			return k, true
		}
	}
	return "", false
}

func parseDoc(h json.RawMessage) map[string]any {
	var doc map[string]any
	if err := json.Unmarshal(h, &doc); err != nil {
		return map[string]any{}
	}
	return doc
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		// Integers come through as float64 from encoding/json; print cleanly.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func upper(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToUpper(s)
	}
	return out
}

func isLevelColumn(c string) bool {
	for _, l := range levelFields {
		if c == l {
			return true
		}
	}
	return false
}

// ANSI colors for log levels.
const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiGray   = "\033[90m"
)

func colorizeLevel(v string, enabled bool) string {
	if !enabled || v == "" {
		return v
	}
	var c string
	switch strings.ToUpper(v) {
	case "ERROR", "ERR", "FATAL", "CRITICAL":
		c = ansiRed
	case "WARN", "WARNING":
		c = ansiYellow
	case "INFO":
		c = ansiGreen
	case "DEBUG", "TRACE":
		c = ansiGray
	default:
		return v
	}
	return c + v + ansiReset
}

// colorEnabled reports whether colorized output should be used: not disabled by
// flag or NO_COLOR, and the writer is a terminal.
func (a *App) colorEnabled() bool {
	if a.NoColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminal(a.Out)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
