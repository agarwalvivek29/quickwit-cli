package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/selfupdate"
)

func newUpgradeCmd(app *App) *cobra.Command {
	var check bool
	var versionOverride string
	var useLatest bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade the qw CLI to match the current context's server",
		Long: "Upgrade the `qw` CLI. By default it reads the version the current context's\n" +
			"qwproxy reports on /health and installs a matching CLI, keeping the CLI in\n" +
			"lockstep with each environment (this may be a downgrade if your CLI is ahead\n" +
			"of that environment). Use --latest for the newest release, or --version to pin\n" +
			"one. The binary is downloaded from GitHub Releases and SHA-256 verified before\n" +
			"it replaces the running one.",
		Example: "  qw upgrade                 # match the current context's server\n" +
			"  qw upgrade --check         # show versions, install nothing\n" +
			"  qw upgrade --latest        # newest published release\n" +
			"  qw upgrade --version v0.3.1",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return app.upgrade(c.Context(), check, versionOverride, useLatest)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "report versions and what would happen, without installing")
	cmd.Flags().StringVar(&versionOverride, "version", "", "install this exact version (e.g. v0.3.1) instead of the server's")
	cmd.Flags().BoolVar(&useLatest, "latest", false, "install the latest GitHub release instead of the context server's version")
	return cmd
}

func (a *App) upgrade(ctx context.Context, check bool, versionOverride string, useLatest bool) error {
	up := selfupdate.New()

	target, source, err := a.upgradeTarget(ctx, up, versionOverride, useLatest)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "current qw: %s\n", version)
	fmt.Fprintf(a.Out, "target:     %s (%s)\n", target, source)

	if selfupdate.Normalize(target) == selfupdate.Normalize(version) {
		fmt.Fprintln(a.Out, "already up to date")
		return nil
	}
	if check {
		fmt.Fprintf(a.Out, "would install %s (run without --check to apply)\n", target)
		return nil
	}

	fmt.Fprintf(a.Err, "downloading and verifying %s...\n", target)
	if err := up.Run(ctx, target); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "upgraded qw to %s\n", target)
	return nil
}

// upgradeTarget resolves which version to install and a human label for where it
// came from.
func (a *App) upgradeTarget(ctx context.Context, up *selfupdate.Updater, versionOverride string, useLatest bool) (target, source string, err error) {
	switch {
	case versionOverride != "":
		return versionOverride, "requested", nil

	case useLatest:
		v, err := up.LatestVersion(ctx)
		if err != nil {
			return "", "", err
		}
		return v, "latest release", nil

	default:
		cctx, _, _, err := a.resolveEffectiveContext()
		if err != nil {
			return "", "", fmt.Errorf("%w\n(no context to read a server version from; use --latest or --version)", err)
		}
		v, err := up.ServerVersion(ctx, a.endpointFor(cctx))
		if err != nil {
			return "", "", fmt.Errorf("could not read the server version for context %q: %w\n"+
				"(use --latest for the newest release, or --version to pin one)", cctx.Name, err)
		}
		return v, fmt.Sprintf("context %q server", cctx.Name), nil
	}
}
