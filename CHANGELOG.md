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
- `qw`: `login`/`login --device`, `context create|list|use|current`, `indexes list|describe|fields`, `search`, `tail`, `count`, `histogram`, `whoami`, `ping`; `-o table|json|raw`, `--fields`, `--since/--from/--to`, level colorization, shell completion.
- `deploy/compose`: local simulation stack (Keycloak + seeded Quickwit + Postgres + qwproxy) and an end-to-end smoke test.
- `install.sh`: one-line installer for the `qw` binary (platform detection, checksum verification), served from the repo via `curl | sh`.
- CI: `docker` workflow publishing the multi-arch `qwproxy` image to GHCR (`:edge` off `main`, semver + `:latest` on tags); `release` workflow running GoReleaser on tags for binaries + checksums.
- `skills/qw`: an agent skill (`qw-logs`) teaching Claude Code to drive `qw`.
- Non-interactive auth for CI/cron: `--token`/`QW_TOKEN` (static bearer), OIDC client-credentials via `--client-secret`/`QW_CLIENT_SECRET`, and `--endpoint`/`QW_ENDPOINT` (+ `QW_ISSUER`/`QW_CLIENT_ID`/`QW_AUDIENCE`) to run with no config file. Precedence: token → client-secret → cached login.
- `qw context delete`; `qw config path|view|edit` (`view` redacts tokens unless `--raw`).
- `qw version` subcommand (honors `-o json`); global `--debug`/`-v` HTTP tracer (bearer redacted); `--jq` built-in jq filter over JSON output; `Example:` blocks on the common commands.

### Changed
- `Dockerfile`: multi-arch, cross-compiling build (`$TARGETARCH`) with version ldflags; `qwproxy` image is now published by `docker.yml` (removed the amd64-only `dockers` block from `.goreleaser.yaml`, which now archives both `qw` and `qwproxy`).
- Pinned `golangci-lint` to v2.12.2 (added `.golangci.yml`, matched `make tools` and CI) so lint is reproducible; fixed the errcheck findings it surfaced.
