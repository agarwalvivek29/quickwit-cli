// Package config loads and saves the qw context file — a kubeconfig-style YAML
// with named contexts and a current-context pointer. One file, many
// environments; tokens are cached inline (the file is written 0600).
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment overrides. EnvConfigPath / EnvContext mirror KUBECONFIG /
// kubectl. The rest let a pipeline or cron authenticate with no interactive
// login (and, with EnvEndpoint + a credential, no config file at all):
//
//	QW_ENDPOINT       proxy/Quickwit base URL (overrides the context endpoint)
//	QW_TOKEN          static bearer token — skip OIDC entirely
//	QW_CLIENT_SECRET  OIDC client-credentials secret — mint+refresh a token
//	QW_ISSUER/QW_CLIENT_ID/QW_AUDIENCE  OIDC config for the no-config CI path
const (
	EnvConfigPath   = "QW_CONFIG"
	EnvContext      = "QW_CONTEXT"
	EnvEndpoint     = "QW_ENDPOINT"
	EnvToken        = "QW_TOKEN"
	EnvClientSecret = "QW_CLIENT_SECRET"
	EnvClientID     = "QW_CLIENT_ID"
	EnvIssuer       = "QW_ISSUER"
	EnvAudience     = "QW_AUDIENCE"
	EnvBearerToken  = "QW_BEARER_TOKEN"
)

// Config is the whole file.
type Config struct {
	CurrentContext string     `yaml:"current-context"`
	Contexts       []*Context `yaml:"contexts"`
}

// Context is one environment: where the proxy is, how to authenticate, and the
// cached tokens from the last `qw login`.
type Context struct {
	Name         string      `yaml:"name"`
	Endpoint     string      `yaml:"endpoint"`
	OIDC         OIDCConfig  `yaml:"oidc"`
	DefaultIndex string      `yaml:"default-index,omitempty"`
	Auth         *AuthTokens `yaml:"auth,omitempty"`
}

// OIDCConfig is the identity-provider config for a context. Only issuer and
// client-id are required; the same values map onto Keycloak (local sim) and
// Okta (prod) unchanged.
type OIDCConfig struct {
	Issuer   string `yaml:"issuer"`
	ClientID string `yaml:"client-id"`
	Audience string `yaml:"audience,omitempty"`
	// BearerToken selects which token the CLI presents to qwproxy: "id-token"
	// (default) sends the OIDC ID token, whose aud is the client id the proxy
	// verifies for per-env isolation; "access-token" sends the access token
	// instead, for a custom authorization server that stamps a real API audience.
	BearerToken string   `yaml:"bearer-token,omitempty"`
	Scopes      []string `yaml:"scopes,omitempty"`
}

// AuthTokens is the cached token set for a context, written by `qw login`.
type AuthTokens struct {
	AccessToken  string    `yaml:"access-token,omitempty"`
	RefreshToken string    `yaml:"refresh-token,omitempty"`
	IDToken      string    `yaml:"id-token,omitempty"`
	TokenType    string    `yaml:"token-type,omitempty"`
	Expiry       time.Time `yaml:"expiry,omitempty"`
}

// ErrNoContext is returned when no context can be resolved.
var ErrNoContext = errors.New("no context selected: run `qw context use <name>` or pass --context")

// DefaultPath is the config file path, honoring QW_CONFIG then XDG_CONFIG_HOME,
// falling back to ~/.config/qw/config.yaml.
func DefaultPath() (string, error) {
	if p := os.Getenv(EnvConfigPath); p != "" {
		return p, nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "qw", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "qw", "config.yaml"), nil
}

// Load reads the config at path. A missing file yields an empty Config (not an
// error) so first-run works without bootstrapping.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}

// Save writes the config to path with 0600 perms, creating parent dirs (0700).
func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	// Write via a temp file + rename so a crash can't leave a half-written,
	// world-readable config; the temp file is created 0600 up front.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("finalize config: %w", err)
	}
	return nil
}

// Context returns the named context, or an error if absent.
func (c *Config) Context(name string) (*Context, error) {
	for _, ctx := range c.Contexts {
		if ctx.Name == name {
			return ctx, nil
		}
	}
	return nil, fmt.Errorf("context %q not found", name)
}

// Resolve picks a context: the override (from --context / QW_CONTEXT) if
// non-empty, else current-context. Errors if neither is set or the name is
// unknown.
func (c *Config) Resolve(override string) (*Context, error) {
	name := override
	if name == "" {
		name = c.CurrentContext
	}
	if name == "" {
		return nil, ErrNoContext
	}
	return c.Context(name)
}

// Upsert adds ctx, or replaces the existing context with the same name.
func (c *Config) Upsert(ctx *Context) {
	for i, existing := range c.Contexts {
		if existing.Name == ctx.Name {
			c.Contexts[i] = ctx
			return
		}
	}
	c.Contexts = append(c.Contexts, ctx)
}

// Delete removes the named context. If it was the current context, the
// current-context pointer is cleared. Returns an error if the context is absent.
func (c *Config) Delete(name string) error {
	for i, ctx := range c.Contexts {
		if ctx.Name == name {
			c.Contexts = append(c.Contexts[:i], c.Contexts[i+1:]...)
			if c.CurrentContext == name {
				c.CurrentContext = ""
			}
			return nil
		}
	}
	return fmt.Errorf("context %q not found", name)
}

// Use sets current-context, requiring the context to exist.
func (c *Config) Use(name string) error {
	if _, err := c.Context(name); err != nil {
		return err
	}
	c.CurrentContext = name
	return nil
}
