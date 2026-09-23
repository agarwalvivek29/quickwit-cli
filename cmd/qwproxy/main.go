// Command qwproxy is the authentication + audit reverse proxy in front of
// Quickwit. It validates an OIDC bearer token on every request, enforces a
// read-only allowlist, streams the upstream response back, and records the
// request envelope (never the response body) to Postgres asynchronously.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/agarwalvivek29/quickwit-cli/internal/apikey"
	"github.com/agarwalvivek29/quickwit-cli/internal/audit"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
	"github.com/agarwalvivek29/quickwit-cli/internal/proxy"
)

// Build info, set via -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := loadConfig()
	if err := cfg.validate(); err != nil {
		return err
	}
	log.Info("starting qwproxy",
		"version", version, "commit", commit, "date", date,
		"listen", cfg.listenAddr, "upstream", cfg.upstream, "issuer", cfg.oidcIssuer,
		"audiences", cfg.expectedAudiences(), "audit_max_conns", cfg.auditMaxConns)
	if len(cfg.expectedAudiences()) == 0 {
		log.Warn("QWPROXY_INSECURE_SKIP_AUDIENCE is set: accepting ANY token the issuer signs " +
			"(any app, any env, any user in the org) — never use this in production")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	upstreamURL, err := url.Parse(cfg.upstream)
	if err != nil {
		return errors.New("invalid QWPROXY_UPSTREAM: " + err.Error())
	}

	// Audit store: connect, apply schema, ensure partitions.
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sink, err := audit.NewPGXSink(initCtx, cfg.auditDSN, audit.PoolConfig{
		MaxConns:          int32(cfg.auditMaxConns),
		MinConns:          int32(cfg.auditMinConns),
		MaxConnLifetime:   time.Duration(cfg.auditConnMaxLifetimeMS) * time.Millisecond,
		MaxConnIdleTime:   time.Duration(cfg.auditConnMaxIdleMS) * time.Millisecond,
		HealthCheckPeriod: time.Duration(cfg.auditHealthcheckMS) * time.Millisecond,
	})
	if err != nil {
		return err
	}
	defer sink.Close()
	if err := sink.EnsureSchema(initCtx); err != nil {
		return err
	}
	if err := sink.EnsurePartitions(initCtx, time.Now().UTC(), cfg.retentionMonths); err != nil {
		return err
	}

	writer := audit.New(sink, audit.Options{
		Buffer:    cfg.auditBuffer,
		BatchSize: cfg.auditBatch,
		Flush:     time.Duration(cfg.auditFlushMS) * time.Millisecond,
		OnError:   func(e error) { log.Warn("audit insert failed", "err", e) },
	})
	writer.Start(ctx)

	// OIDC verifier (discovery happens here). DiscoveryURL/JWKSURL let a
	// locked-down network reach the IdP through an internal gateway while still
	// validating the real, unreachable issuer in the token's `iss` claim.
	verifier, err := oidc.NewVerifier(initCtx, cfg.oidcIssuer, cfg.expectedAudiences(), oidc.Options{
		DiscoveryURL: cfg.oidcDiscoveryURL,
		JWKSURL:      cfg.oidcJWKSURL,
	})
	if err != nil {
		return err
	}

	// API-key store: long-lived keys minted by an OIDC-authenticated user, then
	// authorized by local hash lookup with no OIDC round trip. Enabled whenever a
	// DSN is available (defaults to the audit DSN); the schema self-applies at
	// startup, so a deploy needs no manual migration.
	var keyStore *apikey.Store
	if dsn := cfg.apikeyDSN(); dsn != "" {
		keyStore, err = apikey.NewPGXStore(initCtx, dsn)
		if err != nil {
			return err
		}
		defer keyStore.Close()
		if err := keyStore.EnsureSchema(initCtx); err != nil {
			return err
		}
		log.Info("api-key auth enabled", "max_ttl_days", cfg.apikeyMaxTTLDays)
	} else {
		log.Warn("api-key auth disabled: no audit/api-key DSN configured")
	}

	reg := prometheus.NewRegistry()
	metrics := proxy.NewMetrics(reg, writer)

	opts := proxy.Options{
		Upstream: upstreamURL,
		Verifier: verifier,
		Audit:    writer,
		Metrics:  metrics,
	}
	if keyStore != nil {
		opts.APIKeys = keyStore
	}
	handler := proxy.New(opts)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// version lets `qw upgrade` discover what this context is running so it can
		// install a matching CLI. commit/date are informational.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version,
			"commit":  commit,
			"date":    date,
		})
	})
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// Proxy-native key management (OIDC-only). Mounted before the catch-all so it
	// is never forwarded to Quickwit. Both the bare path and the /{id} form route
	// to the same handler.
	if keyStore != nil {
		admin := proxy.NewAPIKeyAdmin(keyStore, verifier,
			time.Duration(cfg.apikeyMaxTTLDays)*24*time.Hour)
		mux.Handle(proxy.BasePath, admin)
		mux.Handle(proxy.BasePath+"/", admin)
	}
	mux.Handle("/", handler)

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	log.Info("qwproxy listening", "addr", cfg.listenAddr)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
	writer.Close(shutCtx)
	log.Info("audit writer stopped", "written", writer.Written(), "dropped", writer.Dropped())
	return nil
}

type config struct {
	listenAddr string
	upstream   string
	oidcIssuer string
	// oidcClientID is this deployment's OIDC client id, enforced as the token
	// `aud`. The CLI presents its ID token, whose aud is the client id — unique
	// per app/env — so a token minted for one environment is rejected by another.
	oidcClientID string
	// oidcClientIDs is an optional additional set of accepted client ids (aud),
	// so one deployment can front several callers — e.g. the qw CLI plus a
	// Grafana service identity. Any token whose aud matches one of these (or
	// oidcClientID / oidcAudience) is accepted.
	oidcClientIDs []string
	// oidcAudience is the legacy expected audience (an API audience on a custom
	// authorization server). oidcClientID takes precedence; see expectedAudience.
	oidcAudience string
	// insecureSkipAudience disables the aud check entirely. Dev-only escape hatch;
	// without it the proxy refuses to start when no audience is configured.
	insecureSkipAudience bool
	oidcDiscoveryURL     string
	oidcJWKSURL          string
	auditDSN             string
	// apiKeyDSN is the Postgres DSN for the API-key store; empty falls back to
	// auditDSN (they normally share one database). Empty overall disables keys.
	apiKeyDSN        string
	apikeyMaxTTLDays int
	auditBuffer      int
	auditBatch       int
	auditFlushMS     int
	retentionMonths  int

	// Audit-store Postgres pool sizing. Bounds how many connections qwproxy
	// opens against the audit DB so it cannot exhaust Postgres max_connections.
	auditMaxConns          int
	auditMinConns          int
	auditConnMaxLifetimeMS int
	auditConnMaxIdleMS     int
	auditHealthcheckMS     int
}

// apikeyDSN is the DSN for the API-key store, defaulting to the audit DSN so a
// single Postgres serves both. Empty means API-key auth is disabled.
func (c config) apikeyDSN() string {
	if c.apiKeyDSN != "" {
		return c.apiKeyDSN
	}
	return c.auditDSN
}

// expectedAudiences is the set of token `aud` values the proxy accepts: the
// deployment's OIDC client id(s) (QWPROXY_OIDC_CLIENT_ID + QWPROXY_OIDC_CLIENT_IDS)
// — the aud carried by each caller's ID token — plus the legacy API audience
// (QWPROXY_OIDC_AUDIENCE). Empty means no aud check (only valid together with
// insecureSkipAudience).
func (c config) expectedAudiences() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(c.oidcClientID)
	for _, id := range c.oidcClientIDs {
		add(id)
	}
	add(c.oidcAudience)
	return out
}

// validate refuses to start in a fail-open configuration. With no expected
// audience the proxy would accept ANY token the issuer signed — any app, any
// env, any user in the org — which is the "stage token replayed against prod"
// hole. Empty audience is therefore a hard error unless the operator has
// explicitly opted into the insecure dev mode.
func (c config) validate() error {
	if len(c.expectedAudiences()) == 0 && !c.insecureSkipAudience {
		return errors.New("refusing to start: no token audience configured. Set " +
			"QWPROXY_OIDC_CLIENT_ID to this deployment's OIDC client id (the aud the CLI's ID " +
			"token carries) so a token minted for another app/env is rejected; or, for local/dev " +
			"only, set QWPROXY_INSECURE_SKIP_AUDIENCE=true to accept any issuer-signed token")
	}
	return nil
}

func loadConfig() config {
	return config{
		listenAddr:           env("QWPROXY_LISTEN_ADDR", ":9000"),
		upstream:             env("QWPROXY_UPSTREAM", "http://localhost:7280"),
		oidcIssuer:           env("QWPROXY_OIDC_ISSUER", ""),
		oidcClientID:         env("QWPROXY_OIDC_CLIENT_ID", ""),
		oidcClientIDs:        envList("QWPROXY_OIDC_CLIENT_IDS"),
		oidcAudience:         env("QWPROXY_OIDC_AUDIENCE", ""),
		insecureSkipAudience: envBool("QWPROXY_INSECURE_SKIP_AUDIENCE", false),
		oidcDiscoveryURL:     env("QWPROXY_OIDC_DISCOVERY_URL", ""),
		oidcJWKSURL:          env("QWPROXY_OIDC_JWKS_URL", ""),
		auditDSN:             env("QWPROXY_AUDIT_DSN", ""),
		apiKeyDSN:            env("QWPROXY_APIKEY_DSN", ""),
		apikeyMaxTTLDays:     envInt("QWPROXY_APIKEY_MAX_TTL_DAYS", 30),
		auditBuffer:          envInt("QWPROXY_AUDIT_BUFFER", 4096),
		auditBatch:           envInt("QWPROXY_AUDIT_BATCH", 100),
		auditFlushMS:         envInt("QWPROXY_AUDIT_FLUSH_MS", 1000),
		retentionMonths:      envInt("QWPROXY_RETENTION_MONTHS", 12),

		auditMaxConns:          envInt("QWPROXY_AUDIT_MAX_CONNS", 4),
		auditMinConns:          envInt("QWPROXY_AUDIT_MIN_CONNS", 0),
		auditConnMaxLifetimeMS: envInt("QWPROXY_AUDIT_CONN_MAX_LIFETIME_MS", 3600000),
		auditConnMaxIdleMS:     envInt("QWPROXY_AUDIT_CONN_MAX_IDLE_MS", 300000),
		auditHealthcheckMS:     envInt("QWPROXY_AUDIT_HEALTHCHECK_MS", 60000),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envList parses a comma-separated env var into a trimmed, non-empty slice.
func envList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
