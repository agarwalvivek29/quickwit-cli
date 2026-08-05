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
- **Read-only by design** — the CLI and the proxy expose only Quickwit's read surface
  (`version`, list/describe/metadata indexes, search).
- **Log-tailing ergonomics** — `qw tail` (follow), `qw fields` (schema discovery), `qw count` /
  `qw histogram` (volume + trend), `-o table|json|raw`, `--fields a,b,c` projection, `--since 15m`.
- **`qwproxy` audit** — async, non-blocking writes (a slow/absent DB never adds latency to a search),
  bounded buffer with a drop counter, and a monthly-partitioned table with a 12-month retention window.

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

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — dev setup, tests, commit conventions.
- [`docs/`](./docs) — architecture and the deployment model (added as the project grows).

## License

[Apache-2.0](./LICENSE).
