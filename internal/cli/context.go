package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

func newContextCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "context",
		Aliases: []string{"ctx"},
		Short:   "Manage contexts",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List configured contexts",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return app.contextList() },
		},
		&cobra.Command{
			Use:   "use <name>",
			Short: "Set the current context",
			Args:  cobra.ExactArgs(1),
			RunE:  func(c *cobra.Command, args []string) error { return app.contextUse(args[0]) },
		},
		&cobra.Command{
			Use:   "current",
			Short: "Show the current context",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return app.contextCurrent() },
		},
	)
	return cmd
}

func (a *App) contextList() error {
	cfg, _, err := a.loadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Contexts) == 0 {
		fmt.Fprintln(a.Err, "no contexts configured")
		return nil
	}
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CURRENT\tNAME\tENDPOINT\tISSUER\tLOGGED-IN")
	for _, c := range cfg.Contexts {
		marker := ""
		if c.Name == cfg.CurrentContext {
			marker = "*"
		}
		loggedIn := "no"
		if c.Auth != nil && c.Auth.AccessToken != "" {
			loggedIn = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", marker, c.Name, c.Endpoint, c.OIDC.Issuer, loggedIn)
	}
	return tw.Flush()
}

func (a *App) contextUse(name string) error {
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.Use(name); err != nil {
		return err
	}
	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Switched to context %q\n", name)
	return nil
}

func (a *App) contextCurrent() error {
	cfg, _, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.CurrentContext == "" {
		fmt.Fprintln(a.Err, "no current context")
		return nil
	}
	fmt.Fprintln(a.Out, cfg.CurrentContext)
	return nil
}
