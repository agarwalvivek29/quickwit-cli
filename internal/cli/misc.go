package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

func newWhoamiCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the identity of the cached token for the selected context",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return app.whoami() },
	}
}

func newPingCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "ping",
		Short: "Check reachability of the endpoint (and show Quickwit's version)",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return app.ping(c.Context()) },
	}
}

func (a *App) whoami() error {
	cctx, _, _, err := a.resolveContext()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "context:  %s\n", cctx.Name)
	fmt.Fprintf(a.Out, "endpoint: %s\n", cctx.Endpoint)
	if cctx.Auth == nil || cctx.Auth.AccessToken == "" {
		fmt.Fprintln(a.Out, "status:   not logged in (run `qw login`)")
		return nil
	}
	a.printIdentity(cctx)
	return nil
}

func (a *App) ping(ctx context.Context) error {
	client, cctx, err := a.authedClient(ctx)
	if err != nil {
		return err
	}
	v, err := client.Version(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "%s is reachable\n", cctx.Endpoint)
	if build, ok := v["build"].(map[string]any); ok {
		if ver, ok := build["version"].(string); ok {
			fmt.Fprintf(a.Out, "quickwit version: %s\n", ver)
		}
	}
	return nil
}

// --- shared small helpers ---

func writeJSONValue(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func fmtEpochPtr(sec *int64) string {
	if sec == nil {
		return "-"
	}
	return time.Unix(*sec, 0).UTC().Format(time.RFC3339) + " (" + strconv.FormatInt(*sec, 10) + ")"
}
