# quickwit-cli — `qw` + `qwproxy`

A multi-context, OIDC-authenticated **command-line client for [Quickwit](https://quickwit.io)** logs (`qw`),
and a thin **auth + audit reverse proxy** that sits in front of Quickwit (`qwproxy`).

Quickwit OSS ships with **no authentication and no query audit trail** — anything that can reach the
REST API on `:7280` can search (and, with a wider deployment, ingest or delete). `qwproxy` is the layer
that closes both gaps: it validates an OIDC JWT on every request and records the request envelope
(*including the search query itself*) to Postgres — **never the response body**, so your audit DB stays small.
`qw` is the first, best-behaved client of that proxy: `kubectl`/`gcloud`-style contexts, a real browser
login, and log-tailing ergonomics (`tail -f`, field discovery, volume histograms, pipeable output).

```
  qw  ──Bearer JWT──►  qwproxy  ──►  Quickwit /api/v1  (search)
                          │
                          └──►  Postgres  (request envelope + query_body, NO response body)
```

> **Status:** early. Phase 1 is a fully local `docker-compose` simulation (Keycloak stands in for Okta),
> so you can run the entire login → search → audit loop on your laptop before any of it touches a cluster.

## Features

- **Multi-context** — one `~/.config/qw/config.yaml`, many environments; switch with `qw context use <name>`.
- **OIDC login** — Authorization Code + PKCE via a loopback redirect (opens your browser), with a
  Device Authorization Grant fallback (`qw login --device`) for headless/SSH boxes. Works against Okta,
  Keycloak, or any compliant OIDC provider — only the issuer URL changes.
- **Non-interactive auth for CI/cron** — skip the browser entirely: `QW_TOKEN` (a static bearer),
  `QW_CLIENT_SECRET` (OIDC client-credentials, auto-refreshed), and `QW_ENDPOINT` let a pipeline run
  `qw` with no saved config file at all. See [Automation & CI](#automation--ci).
- **Read-only by design** — the CLI and the proxy expose only Quickwit's read surface
  (`version`, list/describe/metadata indexes, search).
- **Log-tailing ergonomics** — `qw tail` (follow), `qw fields` (schema discovery), `qw count` /
  `qw histogram` (volume + trend), `-o table|json|raw`, `--fields a,b,c` projection, `--since 15m`.
- **`qwproxy` audit** — async, non-blocking writes (a slow/absent DB never adds latency to a search),
  bounded buffer with a drop counter, and a monthly-partitioned table with a 12-month retention window.

## Install

**`qw` CLI** (macOS/Linux, amd64/arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/agarwalvivek29/quickwit-cli/main/install.sh | sh
```

The script grabs the right binary from the latest [release](https://github.com/agarwalvivek29/quickwit-cli/releases), verifies its checksum, and installs to `/usr/local/bin` (or `~/.local/bin`). Pin a version with `QW_VERSION=v0.2.0` or change the target with `BINDIR=~/bin`. From source: `go install github.com/agarwalvivek29/quickwit-cli/cmd/qw@latest`.

**`qwproxy` image** (multi-arch, published to GHCR):

```sh
docker pull ghcr.io/agarwalvivek29/qwproxy:latest   # or :edge for the latest main build
```

## Quickstart (local simulation)

Requires Docker + Docker Compose and Go 1.26+.

```sh
make sim-up          # keycloak + quickwit (seeded) + postgres + qwproxy
make build           # build ./bin/qw and ./bin/qwproxy
./bin/qw context use local
./bin/qw login       # browser → Keycloak → token cached in your context
./bin/qw search core-logs 'level:ERROR' --since 1h
./bin/qw tail core-logs '*'
make sim-down
```

## Automation & CI

No browser, no saved config — authenticate straight from the environment:

```sh
# Static bearer token (e.g. a GitHub Actions OIDC id-token, or one minted elsewhere)
export QW_ENDPOINT=https://qwproxy.internal
export QW_TOKEN=eyJhbGciOi...
qw search core-logs 'level:ERROR' --since 1h -o json

# OIDC client-credentials (a service account) — auto-refreshing, ideal for cron
export QW_ENDPOINT=https://qwproxy.internal
export QW_ISSUER=https://acme.okta.com QW_CLIENT_ID=qw-ci QW_AUDIENCE=quickwit-api
export QW_CLIENT_SECRET=...            # keep in a secret store, not a flag
qw count core-logs 'status:[500 TO 599]' --since 1d
```

Precedence: `QW_TOKEN` → stored API key (see below) → `QW_CLIENT_SECRET` → cached
`qw login` tokens. Flags (`--endpoint`, `--token`, `--client-secret`, `--api-key`,
`--context`) override the matching env var. Add `--debug`/`-v` to trace each HTTP
request (the bearer and API key are redacted). `--jq '<expr>'` filters JSON output
with a built-in jq engine (no `jq` binary needed).

## API keys (long-lived, no OIDC to use)

To give a developer or agent read access **without an interactive OIDC login every
time**, mint a long-lived API key. You log in once with OIDC to prove you're a
legitimate user; the key it mints is then presented in an `X-API-Key` header and
the proxy authorizes it by a local lookup — no OIDC validation on that path.

```sh
qw login                       # OIDC, once — proves you're you
qw apikey create --ttl-days 30 # mint a key (max 30d); saved to the current context
qw search core-logs 'level:ERROR' --since 1h   # now authenticates with the key

qw apikey list                 # your keys: id, prefix, expiry, last-used, status
qw apikey revoke <id>          # kill a key immediately
```

`create` saves the key straight into your context's `auth:` block, so subsequent
commands use it automatically — no env var to set. To hand the key to someone else
(CI, a container), copy it from the `create` output (shown once) and set
`QW_API_KEY` there, or pass `--api-key`. Keys are stored on the server as a
SHA-256 hash only, are capped at 30 days (`QWPROXY_APIKEY_MAX_TTL_DAYS`), and every
call they make is attributed to you in the audit trail. Server-side the feature is
enabled automatically when the proxy has a database (it reuses the audit DSN, or
set `QWPROXY_APIKEY_DSN`); the `qw_api_keys` table self-applies at startup.

## Configuration

`qw` keeps its contexts and cached tokens in one YAML file (kubeconfig-style), resolved in order:

```
--config <path>   →   $QW_CONFIG   →   $XDG_CONFIG_HOME/qw/config.yaml   →   ~/.config/qw/config.yaml
```

**Browser login redirect.** `qw login` uses a fixed loopback redirect, `http://127.0.0.1:8765/callback`, which must be registered as a Sign-in redirect URI on your OIDC app. It is deliberately a *fixed* port (not an ephemeral one, and not a wildcard) because providers such as Okta require the redirect URI — port included — to match exactly. Override it with `qw login --redirect-port <port>` (or `QW_REDIRECT_PORT`) and register the matching URI. Headless hosts skip redirects entirely with `qw login --device`. Confidential OIDC clients (e.g. an Okta "Web" app) additionally need their secret at token exchange — pass it via `--client-secret` / `QW_CLIENT_SECRET`.

**Per-environment isolation (audience).** The proxy verifies each token's audience against **this deployment's OIDC client id** (`QWPROXY_OIDC_CLIENT_ID`) and **refuses to start without one** — set the legacy `QWPROXY_OIDC_AUDIENCE`, or the dev-only `QWPROXY_INSECURE_SKIP_AUDIENCE=true`, if you really mean to skip it. To match, `qw` sends its OIDC **ID token** as the bearer by default: an ID token's `aud` is the client id, unique per app/env, so a token minted for stage is rejected by the prod proxy (and vice versa). Point one context at a different env's proxy and its token is turned away at the door. A custom authorization server that already stamps a real API audience on its access tokens can opt back in per context with `oidc.bearer-token: access-token` (or `QW_BEARER_TOKEN=access-token`).

## Handy commands

```sh
qw version -o json                 # build info, scriptable
qw apikey create --ttl-days 30     # mint a long-lived key (see API keys above)
qw upgrade --check                 # is my CLI in sync with this context's server?
qw upgrade                         # install the version the context's server runs
qw config path                     # where is my config file?
qw config view                     # dump it (tokens redacted; --raw to reveal)
qw config edit                     # open it in $EDITOR
qw context delete <name>           # remove a context
qw completion zsh > _qw            # shell completion (bash|zsh|fish|powershell)
```

## Layout

| Path | What |
|------|------|
| `cmd/qw` | the CLI binary |
| `cmd/qwproxy` | the auth + audit proxy |
| `internal/qw` | Quickwit REST client (shared) |
| `internal/oidc` | PKCE + device login (CLI) and JWKS verification (proxy) |
| `internal/config` | context file load/save |
| `internal/audit` | async Postgres writer + schema |
| `internal/timeparse` | `--since 15m` → epoch seconds |
| `deploy/compose` | the local simulation stack |

## Documentation

- [`docs/EXAMPLES.md`](./docs/EXAMPLES.md) — a real, captured first run of `qw` through the proxy (search, tail, histogram, and the audit trail it produces). Start here.
- [`skills/`](./skills) — an agent skill (`qw-logs`) that teaches Claude Code to drive `qw` effectively.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — dev setup, tests, commit conventions.
- Reproduce the examples locally: `make sim-up && make demo`.

## License

[Apache-2.0](./LICENSE).
