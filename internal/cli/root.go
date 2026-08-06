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
			// Flags win; otherwise fall back to the QW_* environment.
			if app.ContextOverride == "" {
				app.ContextOverride = os.Getenv(config.EnvContext)
			}
			if app.Endpoint == "" {
				app.Endpoint = os.Getenv(config.EnvEndpoint)
			}
			if app.Token == "" {
				app.Token = os.Getenv(config.EnvToken)
			}
			if app.ClientSecret == "" {
				app.ClientSecret = os.Getenv(config.EnvClientSecret)
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
	pf.StringVar(&app.JQ, "jq", "", "apply a jq expression to JSON output (implies -o json)")
	pf.BoolVarP(&app.Debug, "debug", "v", false, "trace HTTP requests/responses to stderr")
	pf.StringVar(&app.Endpoint, "endpoint", "", "endpoint base URL, overriding the context (env QW_ENDPOINT)")
	pf.StringVar(&app.Token, "token", "", "static bearer token; skips OIDC (env QW_TOKEN)")
	pf.StringVar(&app.ClientSecret, "client-secret", "", "OIDC client-credentials secret for CI/cron (env QW_CLIENT_SECRET)")

	root.AddCommand(
		newLoginCmd(app),
		newContextCmd(app),
		newConfigCmd(app),
		newIndexesCmd(app),
		newSearchCmd(app),
		newTailCmd(app),
		newCountCmd(app),
		newHistogramCmd(app),
		newWhoamiCmd(app),
		newPingCmd(app),
		newVersionCmd(app),
	)
	return root
}
