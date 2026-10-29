package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// serviceAccountsPath is the proxy's service-account admin endpoint (see
// proxy.ServiceAccountsPath). Every call stays on this base path, using query
// params, so a fronting gateway needs only one route.
const serviceAccountsPath = "/qwproxy/serviceaccounts"

// staleAfter is when `qw sa key list` flags an active key as unused. It mirrors
// qwproxy's default QWPROXY_SA_STALE_DAYS.
const staleAfter = 90 * 24 * time.Hour

func newServiceAccountCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "serviceaccount",
		Aliases: []string{"sa", "serviceaccounts"},
		Short:   "Manage service accounts: API-key identities for agents and bots (admins only)",
		Long: "Manage qwproxy service accounts.\n\n" +
			"A service account is a non-human identity (an agent, a bot, a CI job) that\n" +
			"owns API keys in place of a person, so its calls are audited as\n" +
			"`sa:<name>` and keep working when the admin who made it leaves. Keys can\n" +
			"last 30d, 90d or never expire (the proxy decides which are allowed).\n\n" +
			"Every command uses your OIDC login, and the proxy only accepts members of\n" +
			"its configured admin groups.",
	}

	var description string
	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a service account",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.saCreate(c.Context(), args[0], description)
		},
	}
	createCmd.Flags().StringVar(&description, "description", "", "what the service account is for")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List service accounts",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return app.saList(c.Context()) },
	}

	disableCmd := &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a service account; all of its keys stop working immediately",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.saDisable(c.Context(), args[0]) },
	}

	cmd.AddCommand(createCmd, listCmd, disableCmd, newServiceAccountKeyCmd(app))
	return cmd
}

func newServiceAccountKeyCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "key",
		Aliases: []string{"keys"},
		Short:   "Manage a service account's API keys",
	}

	var ttl, description string
	createCmd := &cobra.Command{
		Use:   "create <service-account>",
		Short: "Mint an API key for a service account (shown once)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.saKeyCreate(c.Context(), args[0], ttl, description)
		},
	}
	createCmd.Flags().StringVar(&ttl, "ttl", "", "key lifetime: 30d, 90d or never (the proxy decides which are allowed)")
	createCmd.Flags().StringVar(&description, "description", "", "human-readable label stored with the key")
	_ = createCmd.MarkFlagRequired("ttl")

	listCmd := &cobra.Command{
		Use:   "list <service-account>",
		Short: "List a service account's keys",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.saKeyList(c.Context(), args[0]) },
	}

	revokeCmd := &cobra.Command{
		Use:   "revoke <service-account> <key-id>",
		Short: "Revoke one of a service account's keys",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			return app.saKeyRevoke(c.Context(), args[0], args[1])
		},
	}

	cmd.AddCommand(createCmd, listCmd, revokeCmd)
	return cmd
}

func saPath(params url.Values) string {
	if len(params) == 0 {
		return serviceAccountsPath
	}
	return serviceAccountsPath + "?" + params.Encode()
}

func (a *App) saCreate(ctx context.Context, name, description string) error {
	req := map[string]any{"name": name}
	if description != "" {
		req["description"] = description
	}
	var sa struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := a.adminRequest(ctx, http.MethodPost, serviceAccountsPath, req, &sa); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "created service account %s (id %s)\n", sa.Name, sa.ID)
	fmt.Fprintf(a.Err, "Mint a key with: qw sa key create %s --ttl 30d|90d|never\n", sa.Name)
	return nil
}

func (a *App) saList(ctx context.Context) error {
	var resp struct {
		ServiceAccounts []struct {
			ID          string     `json:"id"`
			Name        string     `json:"name"`
			Description string     `json:"description"`
			CreatedBy   string     `json:"created_by"`
			CreatedAt   time.Time  `json:"created_at"`
			DisabledAt  *time.Time `json:"disabled_at"`
			ActiveKeys  int        `json:"active_keys"`
			LastUsedAt  *time.Time `json:"last_used_at"`
		} `json:"service_accounts"`
	}
	if err := a.adminRequest(ctx, http.MethodGet, serviceAccountsPath, nil, &resp); err != nil {
		return err
	}
	if a.Output == outJSON {
		return writeJSONValue(a.Out, resp.ServiceAccounts)
	}
	if len(resp.ServiceAccounts) == 0 {
		fmt.Fprintln(a.Err, "no service accounts")
		return nil
	}
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDESCRIPTION\tCREATED BY\tACTIVE KEYS\tLAST USED\tSTATUS")
	for _, sa := range resp.ServiceAccounts {
		status := "active"
		if sa.DisabledAt != nil {
			status = "disabled"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			sa.Name, dashIfEmpty(sa.Description), sa.CreatedBy, sa.ActiveKeys, fmtTimePtr(sa.LastUsedAt), status)
	}
	return tw.Flush()
}

func (a *App) saDisable(ctx context.Context, name string) error {
	if err := a.adminRequest(ctx, http.MethodDelete, saPath(url.Values{"name": {name}}), nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "disabled service account %s; all of its keys are now invalid\n", name)
	return nil
}

func (a *App) saKeyCreate(ctx context.Context, name, ttl, description string) error {
	req := map[string]any{"ttl": ttl}
	if description != "" {
		req["description"] = description
	}
	var created struct {
		ID        string     `json:"id"`
		APIKey    string     `json:"api_key"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := a.adminRequest(ctx, http.MethodPost, saPath(url.Values{"name": {name}}), req, &created); err != nil {
		return err
	}
	if a.Output == outJSON {
		return writeJSONValue(a.Out, created)
	}
	fmt.Fprintf(a.Out, "API key created for service account %s.\n", name)
	fmt.Fprintf(a.Out, "  id:      %s\n", created.ID)
	fmt.Fprintf(a.Out, "  expires: %s\n", fmtExpiry(created.ExpiresAt))
	fmt.Fprintf(a.Out, "\nThe key is shown once — store it in the agent's secret store now:\n\n  %s\n\n", created.APIKey)
	fmt.Fprintln(a.Err, "The agent authenticates with QW_API_KEY=<key> (or --api-key). It is not saved to your context.")
	return nil
}

func (a *App) saKeyList(ctx context.Context, name string) error {
	var resp struct {
		APIKeys []struct {
			ID          string     `json:"id"`
			Prefix      string     `json:"prefix"`
			Description string     `json:"description"`
			CreatedAt   time.Time  `json:"created_at"`
			ExpiresAt   *time.Time `json:"expires_at"`
			RevokedAt   *time.Time `json:"revoked_at"`
			LastUsedAt  *time.Time `json:"last_used_at"`
			CreatedBy   string     `json:"created_by"`
		} `json:"api_keys"`
	}
	if err := a.adminRequest(ctx, http.MethodGet, saPath(url.Values{"name": {name}}), nil, &resp); err != nil {
		return err
	}
	if a.Output == outJSON {
		return writeJSONValue(a.Out, resp.APIKeys)
	}
	if len(resp.APIKeys) == 0 {
		fmt.Fprintf(a.Err, "service account %s has no keys\n", name)
		return nil
	}
	now := time.Now()
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPREFIX\tDESCRIPTION\tCREATED BY\tEXPIRES\tLAST USED\tSTATUS")
	for _, k := range resp.APIKeys {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			k.ID, k.Prefix, dashIfEmpty(k.Description), dashIfEmpty(k.CreatedBy),
			fmtExpiry(k.ExpiresAt), fmtTimePtr(k.LastUsedAt),
			keyStatus(now, k.ExpiresAt, k.RevokedAt, k.LastUsedAt, k.CreatedAt))
	}
	return tw.Flush()
}

func (a *App) saKeyRevoke(ctx context.Context, name, keyID string) error {
	path := saPath(url.Values{"name": {name}, "key_id": {keyID}})
	if err := a.adminRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "revoked key %s of service account %s\n", keyID, name)
	return nil
}

// keyStatus is a key's display status. An active key unused for staleAfter (a
// never-used key counts from creation) is "stale": a prompt to revoke it.
func keyStatus(now time.Time, expiresAt, revokedAt, lastUsedAt *time.Time, createdAt time.Time) string {
	switch {
	case revokedAt != nil:
		return "revoked"
	case expiresAt != nil && !expiresAt.After(now):
		return "expired"
	}
	since := createdAt
	if lastUsedAt != nil {
		since = *lastUsedAt
	}
	if now.Sub(since) > staleAfter {
		return "stale"
	}
	return "active"
}

func fmtExpiry(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}
