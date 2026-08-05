package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/qw"
	"github.com/agarwalvivek29/quickwit-cli/internal/timeparse"
)

// timeFlags are the shared time-window flags. An empty window defaults to the
// last 15 minutes (Quickwit needs a time bound for efficient split pruning).
type timeFlags struct {
	since string
	from  string
	to    string
}

func (t *timeFlags) register(cmd *cobra.Command, defaultSince string) {
	cmd.Flags().StringVar(&t.since, "since", defaultSince, "relative window from now, e.g. 15m, 2h, 1d")
	cmd.Flags().StringVar(&t.from, "from", "", "start time (epoch, RFC3339, YYYY-MM-DD, or a duration ago)")
	cmd.Flags().StringVar(&t.to, "to", "", "end time (epoch, RFC3339, YYYY-MM-DD, 'now', or a duration ago)")
}

func (t *timeFlags) resolve(now time.Time) (start, end *int64, err error) {
	since := t.since
	if since == "" && t.from == "" && t.to == "" {
		since = "15m"
	}
	switch {
	case t.from != "":
		v, e := timeparse.Absolute(t.from, now)
		if e != nil {
			return nil, nil, fmt.Errorf("--from: %w", e)
		}
		start = &v
	case since != "":
		v, e := timeparse.Since(since, now)
		if e != nil {
			return nil, nil, fmt.Errorf("--since: %w", e)
		}
		start = &v
	}
	if t.to != "" {
		v, e := timeparse.Absolute(t.to, now)
		if e != nil {
			return nil, nil, fmt.Errorf("--to: %w", e)
		}
		end = &v
	}
	return start, end, nil
}

// indexQuery resolves the (index, query) pair from positional args, using the
// context's default index when only a query is given.
func indexQuery(defaultIndex string, args []string) (string, string, error) {
	switch len(args) {
	case 2:
		return args[0], args[1], nil
	case 1:
		if defaultIndex == "" {
			return "", "", fmt.Errorf("no index given and the context has no default-index; use `qw search <index> <query>`")
		}
		return defaultIndex, args[0], nil
	default:
		return "", "", fmt.Errorf("expected <index> <query> (or just <query> with a default index)")
	}
}

func newSearchCmd(app *App) *cobra.Command {
	var tf timeFlags
	var maxHits, offset int
	var sortBy, searchField string
	var explain bool

	cmd := &cobra.Command{
		Use:   "search [index] <query>",
		Short: "Search logs",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			client, cctx, err := app.authedClient(c.Context())
			if err != nil {
				return err
			}
			index, query, err := indexQuery(cctx.DefaultIndex, args)
			if err != nil {
				return err
			}
			start, end, err := tf.resolve(time.Now())
			if err != nil {
				return err
			}
			req := qw.SearchRequest{Query: query, MaxHits: maxHits, StartTimestamp: start, EndTimestamp: end, SortBy: sortBy, SearchField: searchField}
			if offset > 0 {
				req.StartOffset = &offset
			}
			if explain {
				app.explain(index, req)
			}
			resp, err := client.Search(c.Context(), index, req)
			if err != nil {
				return err
			}
			fmt.Fprintf(app.Err, "%d hits (showing %d) in %.0fms\n", resp.NumHits, len(resp.Hits), float64(resp.ElapsedTimeMicros)/1000)
			return app.renderHits(resp.Hits)
		},
	}
	tf.register(cmd, "15m")
	cmd.Flags().IntVar(&maxHits, "max-hits", 20, "maximum hits to return")
	cmd.Flags().IntVar(&offset, "offset", 0, "pagination offset")
	cmd.Flags().StringVar(&sortBy, "sort-by", "", "field to sort by")
	cmd.Flags().StringVar(&searchField, "search-field", "", "default field(s) to search, comma-separated")
	cmd.Flags().BoolVar(&explain, "explain", false, "print the index and query sent to Quickwit")
	return cmd
}

func newCountCmd(app *App) *cobra.Command {
	var tf timeFlags
	cmd := &cobra.Command{
		Use:   "count [index] <query>",
		Short: "Count matching logs",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			client, cctx, err := app.authedClient(c.Context())
			if err != nil {
				return err
			}
			index, query, err := indexQuery(cctx.DefaultIndex, args)
			if err != nil {
				return err
			}
			start, end, err := tf.resolve(time.Now())
			if err != nil {
				return err
			}
			resp, err := client.Search(c.Context(), index, qw.SearchRequest{Query: query, MaxHits: 0, StartTimestamp: start, EndTimestamp: end})
			if err != nil {
				return err
			}
			fmt.Fprintln(app.Out, resp.NumHits)
			return nil
		},
	}
	tf.register(cmd, "15m")
	return cmd
}

func newHistogramCmd(app *App) *cobra.Command {
	var tf timeFlags
	var interval string
	cmd := &cobra.Command{
		Use:     "histogram [index] <query>",
		Aliases: []string{"hist"},
		Short:   "Show matching log volume over time",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			return app.runHistogram(c.Context(), args, &tf, interval)
		},
	}
	tf.register(cmd, "1h")
	cmd.Flags().StringVar(&interval, "interval", "1m", "bucket width, e.g. 30s, 1m, 5m, 1h")
	return cmd
}

func (a *App) runHistogram(ctx context.Context, args []string, tf *timeFlags, interval string) error {
	client, cctx, err := a.authedClient(ctx)
	if err != nil {
		return err
	}
	index, query, err := indexQuery(cctx.DefaultIndex, args)
	if err != nil {
		return err
	}
	tsField, err := timestampField(ctx, client, index)
	if err != nil {
		return err
	}
	start, end, err := tf.resolve(time.Now())
	if err != nil {
		return err
	}
	aggs, _ := json.Marshal(map[string]any{
		"histogram": map[string]any{
			"date_histogram": map[string]any{"field": tsField, "fixed_interval": interval},
		},
	})
	resp, err := client.Search(ctx, index, qw.SearchRequest{Query: query, MaxHits: 0, StartTimestamp: start, EndTimestamp: end, Aggs: aggs})
	if err != nil {
		return err
	}
	var parsed struct {
		Histogram struct {
			Buckets []struct {
				KeyAsString string  `json:"key_as_string"`
				Key         float64 `json:"key"`
				DocCount    int64   `json:"doc_count"`
			} `json:"buckets"`
		} `json:"histogram"`
	}
	if len(resp.Aggregations) > 0 {
		_ = json.Unmarshal(resp.Aggregations, &parsed)
	}
	if len(parsed.Histogram.Buckets) == 0 {
		fmt.Fprintln(a.Err, "no data in window")
		return nil
	}
	var max int64
	for _, b := range parsed.Histogram.Buckets {
		if b.DocCount > max {
			max = b.DocCount
		}
	}
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	for _, b := range parsed.Histogram.Buckets {
		label := b.KeyAsString
		if label == "" {
			label = time.UnixMilli(int64(b.Key)).UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\n", label, b.DocCount, bar(b.DocCount, max, 40))
	}
	return tw.Flush()
}

func newTailCmd(app *App) *cobra.Command {
	var tf timeFlags
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "tail [index] <query>",
		Short: "Follow logs (poll-based; Ctrl-C to stop)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			return app.runTail(c.Context(), args, &tf, interval)
		},
	}
	tf.register(cmd, "5m")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "poll interval")
	return cmd
}

func (a *App) runTail(ctx context.Context, args []string, tf *timeFlags, interval time.Duration) error {
	client, cctx, err := a.authedClient(ctx)
	if err != nil {
		return err
	}
	index, query, err := indexQuery(cctx.DefaultIndex, args)
	if err != nil {
		return err
	}
	tsField, err := timestampField(ctx, client, index)
	if err != nil {
		return err
	}

	start, _, err := tf.resolve(time.Now())
	if err != nil {
		return err
	}
	const overlap = int64(5) // seconds of window overlap to catch stragglers
	seen := make(map[string]struct{})

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		now := time.Now().Unix()
		resp, err := client.Search(ctx, index, qw.SearchRequest{
			Query: query, MaxHits: 500, StartTimestamp: start, EndTimestamp: &now, SortBy: tsField,
		})
		if err != nil {
			return err
		}
		hits := chronological(resp.Hits, tsField)
		var maxTS int64
		for _, h := range hits {
			key := string(h.raw)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			_ = a.renderRaw([]json.RawMessage{h.raw})
			if h.ts > maxTS {
				maxTS = h.ts
			}
		}
		if maxTS > 0 {
			ns := maxTS - overlap
			start = &ns
		}
		if len(seen) > 5000 { // keep the dedup set bounded
			seen = make(map[string]struct{})
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// --- helpers ---

func (a *App) explain(index string, req qw.SearchRequest) {
	b, _ := json.MarshalIndent(req, "", "  ")
	fmt.Fprintf(a.Err, "index: %s\nquery:\n%s\n", index, b)
}

// timestampField returns the index's timestamp field, needed by histogram/tail.
func timestampField(ctx context.Context, client *qw.Client, index string) (string, error) {
	// A comma/glob index selects multiple indexes; describe needs a single id,
	// so fall back to metadata of the first if needed.
	d, err := client.DescribeIndex(ctx, index)
	if err == nil && d.TimestampFieldName != "" {
		return d.TimestampFieldName, nil
	}
	m, err := client.GetIndexMetadata(ctx, index)
	if err != nil {
		return "", err
	}
	if m.IndexConfig.DocMapping.TimestampField == "" {
		return "", fmt.Errorf("index %q has no timestamp field", index)
	}
	return m.IndexConfig.DocMapping.TimestampField, nil
}

type tsHit struct {
	raw json.RawMessage
	ts  int64
}

// chronological parses each hit's timestamp (best-effort) and returns hits
// sorted oldest-first.
func chronological(hits []json.RawMessage, tsField string) []tsHit {
	out := make([]tsHit, len(hits))
	for i, h := range hits {
		out[i] = tsHit{raw: h, ts: parseHitTS(h, tsField)}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ts < out[j].ts })
	return out
}

func parseHitTS(h json.RawMessage, tsField string) int64 {
	doc := parseDoc(h)
	v, ok := doc[tsField]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		if t > 1e12 { // looks like millis
			return int64(t) / 1000
		}
		return int64(t)
	case string:
		if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return ts.Unix()
		}
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func bar(n, max int64, width int) string {
	if max == 0 {
		return ""
	}
	fill := int(n * int64(width) / max)
	b := make([]byte, fill)
	for i := range b {
		b[i] = '#'
	}
	return string(b)
}
