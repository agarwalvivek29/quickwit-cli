# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-09-23

### Added
- **Long-lived API keys** for access without an interactive OIDC login. An OIDC-authenticated user mints a key with `qw apikey create` (`--ttl-days`, capped at 30 / `QWPROXY_APIKEY_MAX_TTL_DAYS`); it is saved to the current context and presented in an `X-API-Key` header, which the proxy authorizes by a local SHA-256 hash lookup with **no OIDC validation** on that path. Management (`qw apikey create|list|revoke`, served at `POST|GET|DELETE /qwproxy/apikeys`) requires an OIDC bearer — a key can never mint or manage another key. Keys are stored hashed, are scoped to the same read-only allowlist, and every call is attributed to the creator in the audit trail (new `auth_method` column). Enabled automatically when the proxy has a database (reuses the audit DSN, or `QWPROXY_APIKEY_DSN`); the `qw_api_keys` schema self-applies at startup. New: `--api-key`/`QW_API_KEY` override; precedence is `QW_TOKEN` → stored/`QW_API_KEY` key → `QW_CLIENT_SECRET` → cached login.
- **`qw upgrade`** keeps the CLI in lockstep with each environment. By default it reads the version the current context's qwproxy now advertises on `/health` and installs a matching `qw` (a downgrade if the CLI is ahead of that environment); `--latest` picks the newest GitHub release, `--version` pins one, and `--check` previews without installing. The binary is pulled from GitHub Releases using the same asset layout as `install.sh` and **SHA-256-verified against `checksums.txt` (fail-closed) before atomically replacing the running binary**. qwproxy's `/health` now includes `version`/`commit`/`date`.

## [0.4.0] - 2026-09-17

### Security
- **qwproxy enforces the token audience and fails closed.** Previously an empty `QWPROXY_OIDC_AUDIENCE` skipped the audience check, so *any* token the issuer signed — any app, any env, any user in the org — was accepted (the "stage token replayed against prod" hole). The proxy now **refuses to start** unless it has an expected audience: set `QWPROXY_OIDC_CLIENT_ID` to the deployment's OIDC client id (recommended), the legacy `QWPROXY_OIDC_AUDIENCE` (a custom-AS API audience), or the explicit dev-only escape hatch `QWPROXY_INSECURE_SKIP_AUDIENCE=true`.
- **The CLI now presents its OIDC ID token** (not the access token) as the bearer by default. An ID token's `aud` is the app's client id — unique per app/env — so the proxy's `aud` check gives real per-environment isolation (a token minted for one env is rejected by another env's proxy), which an org-authorization-server access token (`aud` = the org URL, identical for every app) cannot. Opt back into the access token per context with `oidc.bearer-token: access-token` / `QW_BEARER_TOKEN` for a custom authorization server. Added an integration test that presents a wrong-`aud` token and asserts 401.

### Added
- Initial project scaffolding: Go module, Apache-2.0 license, CI, release config, contributor docs.
- `internal/qw`: Quickwit REST client (version, list/get/describe indexes, search).
- `internal/oidc`: PKCE loopback + device-grant login, self-persisting refreshing token source, and JWKS-based JWT verification.
- `internal/config`: kubeconfig-style multi-context file (0600, atomic writes).
- `internal/audit`: async, drop-on-full Postgres writer; monthly-partitioned schema with a 12-month retention window.
- `internal/timeparse`: human time expressions (`15m`, RFC3339, epoch, `now`) to epoch seconds.
- `qwproxy`: OIDC auth + read-only allowlist + streaming reverse proxy + request-envelope audit (never response bodies) + Prometheus metrics.
- **qwproxy: Grafana Quickwit datasource support.** The read-only allowlist now also permits the Elasticsearch-compatible read surface the Grafana `quickwit-quickwit-datasource` plugin uses — `POST /api/v1/_elastic/_msearch`, `GET /api/v1/_elastic/{index}/_field_caps`, `GET /api/v1/_elastic/{index}/_mapping` — while ingest/write endpoints (e.g. `_bulk`) stay blocked.
- **qwproxy: multi-audience.** `QWPROXY_OIDC_CLIENT_IDS` (comma-separated) / chart `proxy.oidc.clientIds` lets one proxy accept several client ids at once — e.g. the qw CLI plus a Grafana service identity — in addition to `QWPROXY_OIDC_CLIENT_ID`/`QWPROXY_OIDC_AUDIENCE`. Fail-closed behaviour is unchanged (at least one audience is still required to start).
- **qwproxy: `_msearch` audit fidelity.** `_elastic/_msearch` requests are now audited with the queried index (read from the ndjson header lines) and the query body captured as a JSON array, matching the fidelity of native `/{index}/search`.
- `qw`: `login`/`login --device`, `context create|list|use|current`, `indexes list|describe|fields`, `search`, `tail`, `count`, `histogram`, `whoami`, `ping`; `-o table|json|raw`, `--fields`, `--since/--from/--to`, level colorization, shell completion.
- `deploy/compose`: local simulation stack (Keycloak + seeded Quickwit + Postgres + qwproxy) and an end-to-end smoke test.
- `install.sh`: one-line installer for the `qw` binary (platform detection, checksum verification), served from the repo via `curl | sh`.
- CI: `docker` workflow publishing the multi-arch `qwproxy` image to GHCR (`:edge` off `main`, semver + `:latest` on tags); `release` workflow running GoReleaser on tags for binaries + checksums.
- `skills/qw`: an agent skill (`qw-logs`) teaching Claude Code to drive `qw`.
- Non-interactive auth for CI/cron: `--token`/`QW_TOKEN` (static bearer), OIDC client-credentials via `--client-secret`/`QW_CLIENT_SECRET`, and `--endpoint`/`QW_ENDPOINT` (+ `QW_ISSUER`/`QW_CLIENT_ID`/`QW_AUDIENCE`) to run with no config file. Precedence: token → client-secret → cached login.
- `qw context delete`; `qw config path|view|edit` (`view` redacts tokens unless `--raw`).
- `qw version` subcommand (honors `-o json`); global `--debug`/`-v` HTTP tracer (bearer redacted); `--jq` built-in jq filter over JSON output; `Example:` blocks on the common commands.
- Confidential-client login: `qw login` sends the client secret (`--client-secret` / `QW_CLIENT_SECRET`) at token exchange when set, so it works with confidential OIDC apps (e.g. an Okta "Web" app), not just public/PKCE clients.

### Changed
- `qw login` browser flow now uses a **fixed** loopback redirect (`http://127.0.0.1:8765/callback`, override with `--redirect-port` / `QW_REDIRECT_PORT`) instead of an ephemeral port, so it works with providers that require an exactly-registered redirect URI (e.g. Okta, which does not wildcard the loopback port). Register that one URI on the app — no wildcard.
- sim: tightened the Keycloak realm redirect from a port wildcard to the exact `http://127.0.0.1:8765/callback`, matching the CLI default and modelling the no-wildcard pattern.
- Documented the config file location (`~/.config/qw/config.yaml`, honoring `$QW_CONFIG` / `$XDG_CONFIG_HOME`) in the README.
- `Dockerfile`: multi-arch, cross-compiling build (`$TARGETARCH`) with version ldflags; `qwproxy` image is now published by `docker.yml` (removed the amd64-only `dockers` block from `.goreleaser.yaml`, which now archives both `qw` and `qwproxy`).
- Pinned `golangci-lint` to v2.12.2 (added `.golangci.yml`, matched `make tools` and CI) so lint is reproducible; fixed the errcheck findings it surfaced.
