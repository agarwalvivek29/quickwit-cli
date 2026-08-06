package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

const redacted = "REDACTED"

func newConfigCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Locate, inspect, and edit the qw config file",
	}

	var raw bool
	view := &cobra.Command{
		Use:   "view",
		Short: "Print the config file (tokens redacted unless --raw)",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return app.configView(raw) },
	}
	view.Flags().BoolVar(&raw, "raw", false, "show cached tokens unredacted")

	cmd.AddCommand(
		&cobra.Command{
			Use:   "path",
			Short: "Print the resolved config file path",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return app.configPath() },
		},
		view,
		&cobra.Command{
			Use:   "edit",
			Short: "Open the config file in $EDITOR",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return app.configEdit() },
		},
	)
	return cmd
}

// resolvedConfigPath returns the config path in effect (flag, else default).
func (a *App) resolvedConfigPath() (string, error) {
	if a.ConfigPath != "" {
		return a.ConfigPath, nil
	}
	return config.DefaultPath()
}

func (a *App) configPath() error {
	path, err := a.resolvedConfigPath()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Out, path)
	return nil
}

func (a *App) configView(raw bool) error {
	cfg, _, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !raw {
		cfg = redactConfig(cfg)
	}
	enc := yaml.NewEncoder(a.Out)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	return enc.Encode(cfg)
}

func (a *App) configEdit() error {
	path, err := a.resolvedConfigPath()
	if err != nil {
		return err
	}
	editor := firstNonEmpty(os.Getenv("VISUAL"), os.Getenv("EDITOR"), "vi")
	// Editors need the real terminal, not the (possibly redirected) app streams.
	cmd := exec.Command(editor, path) //nolint:gosec // editor is the user's own $EDITOR
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// redactConfig returns a copy of cfg with every cached token replaced by a
// placeholder, so `qw config view` can be pasted into a bug report safely.
func redactConfig(c *config.Config) *config.Config {
	out := &config.Config{CurrentContext: c.CurrentContext}
	for _, ctx := range c.Contexts {
		cp := *ctx
		if cp.Auth != nil {
			auth := *cp.Auth
			if auth.AccessToken != "" {
				auth.AccessToken = redacted
			}
			if auth.RefreshToken != "" {
				auth.RefreshToken = redacted
			}
			if auth.IDToken != "" {
				auth.IDToken = redacted
			}
			cp.Auth = &auth
		}
		out.Contexts = append(out.Contexts, &cp)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
