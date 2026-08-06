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
		newContextCreateCmd(app),
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
		&cobra.Command{
			Use:     "delete <name>",
			Aliases: []string{"rm", "remove"},
			Short:   "Delete a context",
			Args:    cobra.ExactArgs(1),
			RunE:    func(c *cobra.Command, args []string) error { return app.contextDelete(args[0]) },
		},
	)
	return cmd
}

func (a *App) contextDelete(name string) error {
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	wasCurrent := cfg.CurrentContext == name
	if err := cfg.Delete(name); err != nil {
		return err
	}
	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Deleted context %q\n", name)
	if wasCurrent {
		fmt.Fprintln(a.Err, "note: that was the current context; select another with `qw context use <name>`")
	}
	return nil
}

// newContextCreateCmd creates (or updates) a context from flags.
func newContextCreateCmd(app *App) *cobra.Command {
	var (
		endpoint     string
		issuer       string
		clientID     string
		audience     string
		defaultIndex string
		use          bool
	)
	cmd := &cobra.Command{
		Use:     "create <name>",
		Aliases: []string{"add", "set"},
		Short:   "Create or update a context",
		Long: "Create or update a context. --endpoint is required; --issuer and --client-id are\n" +
			"needed before `qw login` will work (you can add them now or re-run to update).",
		Example: "  qw context create prod --endpoint https://qwproxy.internal \\\n" +
			"    --issuer https://acme.okta.com --client-id qw-cli --default-index core-logs --use",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.contextCreate(args[0], config.OIDCConfig{Issuer: issuer, ClientID: clientID, Audience: audience}, endpoint, defaultIndex, use)
		},
	}
	f := cmd.Flags()
	f.StringVar(&endpoint, "endpoint", "", "proxy (or Quickwit) base URL, e.g. https://qwproxy.internal:443 (required)")
	f.StringVar(&issuer, "issuer", "", "OIDC issuer URL")
	f.StringVar(&clientID, "client-id", "", "OIDC client id")
	f.StringVar(&audience, "audience", "", "OIDC audience (optional)")
	f.StringVar(&defaultIndex, "default-index", "", "default index for search/count/tail/histogram")
	f.BoolVar(&use, "use", false, "switch to this context after creating it")
	_ = cmd.MarkFlagRequired("endpoint")
	return cmd
}

func (a *App) contextCreate(name string, oidc config.OIDCConfig, endpoint, defaultIndex string, use bool) error {
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	// Preserve cached tokens when updating an existing context.
	var auth *config.AuthTokens
	prev, prevErr := cfg.Context(name)
	existed := prevErr == nil
	if existed {
		auth = prev.Auth
	}
	cfg.Upsert(&config.Context{
		Name:         name,
		Endpoint:     endpoint,
		OIDC:         oidc,
		DefaultIndex: defaultIndex,
		Auth:         auth,
	})
	if use || cfg.CurrentContext == "" {
		_ = cfg.Use(name)
	}
	if err := config.Save(path, cfg); err != nil {
		return err
	}

	verb := "Created"
	if existed {
		verb = "Updated"
	}
	fmt.Fprintf(a.Out, "%s context %q (endpoint %s)\n", verb, name, endpoint)
	if oidc.Issuer == "" || oidc.ClientID == "" {
		fmt.Fprintln(a.Err, "note: set --issuer and --client-id before running `qw login`")
	} else {
		fmt.Fprintf(a.Out, "Next: qw %slogin\n", contextFlagHint(a, name))
	}
	return nil
}

// contextFlagHint suggests --context in the login hint unless the new context
// is already current.
func contextFlagHint(a *App, name string) string {
	cfg, _, err := a.loadConfig()
	if err == nil && cfg.CurrentContext == name {
		return ""
	}
	return fmt.Sprintf("--context %s ", name)
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
