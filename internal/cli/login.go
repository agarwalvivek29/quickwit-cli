package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/config"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// defaultRedirectPort is the fixed loopback port the browser-login flow uses.
// It is fixed (not ephemeral) because providers like Okta require the redirect
// URI — including the port — to be registered exactly. Register
// http://127.0.0.1:8765/callback in the app; override with --redirect-port.
const defaultRedirectPort = "8765"

func newLoginCmd(app *App) *cobra.Command {
	var device bool
	var redirectPort string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the selected context via OIDC",
		Long: "Authenticate the selected context via OIDC (browser by default; --device for\n" +
			"headless hosts). For CI/cron, skip login entirely and set QW_TOKEN (a static\n" +
			"bearer) or QW_CLIENT_SECRET (client-credentials) instead — see `qw --help`.\n\n" +
			"The browser flow uses a fixed loopback redirect, http://127.0.0.1:8765/callback,\n" +
			"which must be registered in the app (providers like Okta require an exact match).\n" +
			"Override the port with --redirect-port / QW_REDIRECT_PORT.",
		Example: "  qw login\n  qw login --device               # headless/SSH box (device code)\n" +
			"  qw login --redirect-port 9000   # if 8765 is taken / a different URI is registered",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if redirectPort == "" {
				redirectPort = os.Getenv("QW_REDIRECT_PORT")
			}
			if redirectPort == "" {
				redirectPort = defaultRedirectPort
			}
			return app.runLogin(c.Context(), device, redirectPort)
		},
	}
	cmd.Flags().BoolVar(&device, "device", false, "use the device authorization grant (for headless hosts)")
	cmd.Flags().StringVar(&redirectPort, "redirect-port", "", "loopback port for the browser redirect (default 8765; env QW_REDIRECT_PORT); register http://127.0.0.1:<port>/callback in the IdP")
	return cmd
}

func (a *App) runLogin(ctx context.Context, device bool, redirectPort string) error {
	cctx, cfg, path, err := a.resolveContext()
	if err != nil {
		return err
	}
	if cctx.OIDC.Issuer == "" || cctx.OIDC.ClientID == "" {
		return fmt.Errorf("context %q is missing oidc.issuer / oidc.client-id", cctx.Name)
	}

	auth, err := oidc.New(ctx, providerConfig(cctx, a.ClientSecret))
	if err != nil {
		return err
	}
	if !device && redirectPort != "" {
		auth.BindAddr = "127.0.0.1:" + redirectPort
		fmt.Fprintf(a.Err, "Using fixed redirect URI: http://127.0.0.1:%s/callback\n", redirectPort)
	}

	var toks *oidc.Tokens
	if device {
		toks, err = auth.LoginDevice(ctx, func(p oidc.DevicePrompt) {
			uri := p.VerificationURIComplete
			if uri == "" {
				uri = p.VerificationURI
			}
			fmt.Fprintf(a.Err, "To sign in, open:\n  %s\nand enter code: %s\n", uri, p.UserCode)
		})
	} else {
		fmt.Fprintln(a.Err, "Opening your browser to sign in... (use --device on a headless host)")
		toks, err = auth.Login(ctx)
	}
	if err != nil {
		return err
	}

	cctx.Auth = tokensToConfig(toks)
	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Logged in to context %q\n", cctx.Name)
	a.printIdentity(cctx)
	return nil
}

// printIdentity shows who the cached token belongs to (best-effort, no verify).
func (a *App) printIdentity(cctx *config.Context) {
	claims := decodeJWTClaims(cctx.Auth.AccessToken)
	if claims == nil {
		claims = decodeJWTClaims(cctx.Auth.IDToken)
	}
	if claims == nil {
		return
	}
	if email, _ := claims["email"].(string); email != "" {
		fmt.Fprintf(a.Out, "  identity: %s\n", email)
	} else if sub, _ := claims["sub"].(string); sub != "" {
		fmt.Fprintf(a.Out, "  identity: %s\n", sub)
	}
	if exp, ok := claims["exp"].(float64); ok {
		fmt.Fprintf(a.Out, "  token expires: %s\n", time.Unix(int64(exp), 0).Format(time.RFC3339))
	}
}

// decodeJWTClaims decodes a JWT payload WITHOUT verifying the signature — for
// display only (the proxy is the component that actually verifies).
func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}
