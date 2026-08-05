// Command qw is a multi-context, OIDC-authenticated, read-only command-line
// client for searching Quickwit logs.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/agarwalvivek29/quickwit-cli/internal/cli"
)

// Build info, set via -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCmd()
	root.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
