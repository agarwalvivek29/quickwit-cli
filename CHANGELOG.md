# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding: Go module, Apache-2.0 license, CI, release config, contributor docs.
- `internal/qw`: Quickwit REST client (version, list/get/describe indexes, search).
- `internal/oidc`: PKCE loopback + device-grant login, self-persisting refreshing token source, and JWKS-based JWT verification.
- `internal/config`: kubeconfig-style multi-context file (0600, atomic writes).
- `internal/audit`: async, drop-on-full Postgres writer; monthly-partitioned schema with a 12-month retention window.
- `internal/timeparse`: human time expressions (`15m`, RFC3339, epoch, `now`) to epoch seconds.
- `qwproxy`: OIDC auth + read-only allowlist + streaming reverse proxy + request-envelope audit (never response bodies) + Prometheus metrics.
- `qw`: `login`/`login --device`, `context`, `indexes list|describe|fields`, `search`, `tail`, `count`, `histogram`, `whoami`, `ping`; `-o table|json|raw`, `--fields`, `--since/--from/--to`, level colorization, shell completion.
- `deploy/compose`: local simulation stack (Keycloak + seeded Quickwit + Postgres + qwproxy) and an end-to-end smoke test.
