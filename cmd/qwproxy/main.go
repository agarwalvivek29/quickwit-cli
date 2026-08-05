// Command qwproxy is the authentication + audit reverse proxy in front of
// Quickwit. It validates an OIDC bearer token on every request, enforces a
// read-only allowlist, streams the upstream response back, and records the
// request envelope (never the response body) to Postgres asynchronously.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

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
	log.Info("starting qwproxy",
		"version", version, "commit", commit, "date", date,
		"listen", cfg.listenAddr, "upstream", cfg.upstream, "issuer", cfg.oidcIssuer)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	upstreamURL, err := url.Parse(cfg.upstream)
	if err != nil {
		return errors.New("invalid QWPROXY_UPSTREAM: " + err.Error())
	}

	// Audit store: connect, apply schema, ensure partitions.
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sink, err := audit.NewPGXSink(initCtx, cfg.auditDSN)
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

	// OIDC verifier (discovery happens here).
	verifier, err := oidc.NewVerifier(initCtx, cfg.oidcIssuer, cfg.oidcAudience)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	metrics := proxy.NewMetrics(reg, writer)

	handler := proxy.New(proxy.Options{
		Upstream: upstreamURL,
		Verifier: verifier,
		Audit:    writer,
		Metrics:  metrics,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
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
	listenAddr      string
	upstream        string
	oidcIssuer      string
	oidcAudience    string
	auditDSN        string
	auditBuffer     int
	auditBatch      int
	auditFlushMS    int
	retentionMonths int
}

func loadConfig() config {
	return config{
		listenAddr:      env("QWPROXY_LISTEN_ADDR", ":9000"),
		upstream:        env("QWPROXY_UPSTREAM", "http://localhost:7280"),
		oidcIssuer:      env("QWPROXY_OIDC_ISSUER", ""),
		oidcAudience:    env("QWPROXY_OIDC_AUDIENCE", ""),
		auditDSN:        env("QWPROXY_AUDIT_DSN", ""),
		auditBuffer:     envInt("QWPROXY_AUDIT_BUFFER", 4096),
		auditBatch:      envInt("QWPROXY_AUDIT_BATCH", 100),
		auditFlushMS:    envInt("QWPROXY_AUDIT_FLUSH_MS", 1000),
		retentionMonths: envInt("QWPROXY_RETENTION_MONTHS", 12),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
