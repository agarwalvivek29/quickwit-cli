package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
)

// apiKeysPath is the proxy-native management endpoint (see proxy.BasePath).
const apiKeysPath = "/qwproxy/apikeys"

func newAPIKeyCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "apikey",
		Aliases: []string{"api-key", "apikeys"},
		Short:   "Manage long-lived API keys (mint with OIDC, then use without logging in)",
		Long: "Manage qwproxy API keys.\n\n" +
			"`create` uses your OIDC login to mint a key and saves it to the current\n" +
			"context, so subsequent commands authenticate with the key (X-API-Key) and\n" +
			"need no further login until it expires. Hand a key to a developer or agent\n" +
			"that should have read access without an interactive OIDC flow.",
	}

	var ttlDays int
	var description string
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Mint an API key for the current context and save it locally",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return app.apiKeyCreate(c.Context(), ttlDays, description)
		},
	}
	createCmd.Flags().IntVar(&ttlDays, "ttl-days", 30, "requested validity in days (the proxy caps the maximum)")
	createCmd.Flags().StringVar(&description, "description", "", "human-readable label stored with the key")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List the API keys you have minted",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return app.apiKeyList(c.Context()) },
	}

	revokeCmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke one of your API keys",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.apiKeyRevoke(c.Context(), args[0]) },
	}

	cmd.AddCommand(createCmd, listCmd, revokeCmd)
	return cmd
}

// adminRequest makes an OIDC-authenticated call to the proxy's key-management API
// and decodes a JSON 2xx body into out (out may be nil). It always forces the
// OIDC path, so key management works even when a key is already stored.
func (a *App) adminRequest(ctx context.Context, method, path string, body, out any) error {
	cctx, cfg, cfgPath, err := a.resolveEffectiveContext()
	if err != nil {
		return err
	}
	hc, err := a.httpClient(ctx, cctx, cfg, cfgPath, true /* forceOIDC */)
	if err != nil {
		return err
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	u := a.endpointFor(cctx) + path
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("qwproxy returned HTTP %d for %s: %s", resp.StatusCode, u, apiKeyErrMsg(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response from %s: %w", u, err)
		}
	}
	return nil
}

func (a *App) apiKeyCreate(ctx context.Context, ttlDays int, description string) error {
	cctx, cfg, cfgPath, err := a.resolveEffectiveContext()
	if err != nil {
		return err
	}
	if cctx.Name == "(env)" {
		return fmt.Errorf("cannot save an API key without a config-file context; " +
			"create a context first (see `qw context`)")
	}

	var created struct {
		ID        string    `json:"id"`
		APIKey    string    `json:"api_key"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	req := map[string]any{"ttl_days": ttlDays}
	if description != "" {
		req["description"] = description
	}
	if err := a.adminRequest(ctx, http.MethodPost, apiKeysPath, req, &created); err != nil {
		return err
	}

	// Persist the key to the context so subsequent commands use it automatically.
	if cctx.Auth == nil {
		cctx.Auth = &config.AuthTokens{}
	}
	cctx.Auth.APIKey = created.APIKey
	cctx.Auth.APIKeyExpiry = created.ExpiresAt
	if err := config.Save(cfgPath, cfg); err != nil {
		return fmt.Errorf("save api key to config: %w", err)
	}

	fmt.Fprintf(a.Out, "API key created and saved to context %q.\n", cctx.Name)
	fmt.Fprintf(a.Out, "  id:      %s\n", created.ID)
	fmt.Fprintf(a.Out, "  expires: %s\n", created.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(a.Out, "\nThe key is shown once — copy it now to share it:\n\n  %s\n\n", created.APIKey)
	fmt.Fprintln(a.Err, "This context will now authenticate with the key (no OIDC login needed until it expires).")
	return nil
}

func (a *App) apiKeyList(ctx context.Context) error {
	var resp struct {
		APIKeys []struct {
			ID          string     `json:"id"`
			Prefix      string     `json:"prefix"`
			Description string     `json:"description"`
			CreatedAt   time.Time  `json:"created_at"`
			ExpiresAt   time.Time  `json:"expires_at"`
			RevokedAt   *time.Time `json:"revoked_at"`
			LastUsedAt  *time.Time `json:"last_used_at"`
		} `json:"api_keys"`
	}
	if err := a.adminRequest(ctx, http.MethodGet, apiKeysPath, nil, &resp); err != nil {
		return err
	}
	if a.Output == outJSON {
		return writeJSONValue(a.Out, resp.APIKeys)
	}
	if len(resp.APIKeys) == 0 {
		fmt.Fprintln(a.Err, "no api keys")
		return nil
	}
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPREFIX\tDESCRIPTION\tEXPIRES\tLAST USED\tSTATUS")
	for _, k := range resp.APIKeys {
		status := "active"
		switch {
		case k.RevokedAt != nil:
			status = "revoked"
		case !k.ExpiresAt.After(time.Now()):
			status = "expired"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			k.ID, k.Prefix, dashIfEmpty(k.Description),
			k.ExpiresAt.Format(time.RFC3339), fmtTimePtr(k.LastUsedAt), status)
	}
	return tw.Flush()
}

func (a *App) apiKeyRevoke(ctx context.Context, id string) error {
	// Use the ?id= query form (not a /{id} path segment) so revoke stays on the
	// same base path as create/list — that path is what a fronting gateway (e.g.
	// Kong) routes; a sub-path may not be.
	path := apiKeysPath + "?id=" + url.QueryEscape(id)
	if err := a.adminRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "revoked api key %s\n", id)
	return nil
}

// apiKeyErrMsg pulls the {"error":...} message out of a proxy error body, falling
// back to the raw text.
func apiKeyErrMsg(data []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return e.Error
	}
	return string(bytes.TrimSpace(data))
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}
