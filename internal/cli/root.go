package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

// NewRootCmd builds the `qw` command tree.
func NewRootCmd() *cobra.Command {
	app := &App{Out: os.Stdout, Err: os.Stderr}

	root := &cobra.Command{
		Use:           "qw",
		Short:         "Quickwit log CLI — multi-context, OIDC-authenticated, read-only",
		Long:          "qw is a multi-context, OIDC-authenticated command-line client for searching Quickwit logs.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if app.ContextOverride == "" {
				app.ContextOverride = os.Getenv(config.EnvContext)
			}
			switch app.Output {
			case outTable, outJSON, outRaw:
			default:
				return fmt.Errorf("invalid --output %q (want table, json or raw)", app.Output)
			}
			// Route command output through cobra's streams (tests can swap them).
			app.Out = cmd.OutOrStdout()
			app.Err = cmd.ErrOrStderr()
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&app.ConfigPath, "config", "", "config file (default $XDG_CONFIG_HOME/qw/config.yaml)")
	pf.StringVar(&app.ContextOverride, "context", "", "context to use (overrides current-context / QW_CONTEXT)")
	pf.StringVarP(&app.Output, "output", "o", "table", "output format: table|json|raw")
	pf.BoolVar(&app.NoColor, "no-color", false, "disable colored output")
	pf.StringSliceVar(&app.Fields, "fields", nil, "fields to project, comma-separated (dot paths)")

	root.AddCommand(
		newLoginCmd(app),
		newContextCmd(app),
		newIndexesCmd(app),
		newSearchCmd(app),
		newTailCmd(app),
		newCountCmd(app),
		newHistogramCmd(app),
		newWhoamiCmd(app),
		newPingCmd(app),
	)
	return root
}
