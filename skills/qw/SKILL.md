---
name: qw-logs
description: >-
  Search and investigate Quickwit logs from the terminal with the `qw` CLI
  (multi-context, OIDC-authenticated, read-only, through the qwproxy audit
  proxy). Use whenever the user wants to look at logs via `qw` — "search the
  logs", "why is X service erroring", "tail the logs for Y", "any ERRORs in the
  last hour", "log volume / trend for Z", "find this request/trace id", "count
  matching lines", "what fields does this index have", "which indexes exist" —
  or mentions `qw`, `qwproxy`, or Quickwit log search from the CLI. Read-only:
  run the commands and report findings, echoing the index + query used.
---

# qw — Quickwit log CLI

`qw` is a read-only, multi-context, OIDC-authenticated client for Quickwit logs.
It talks to a `qwproxy` endpoint (auth + audit) or directly to Quickwit. It only
ever reads (`version`, list/describe indexes, search) — it cannot ingest or
delete, so every command here is safe to run.

## First: is a context set up and logged in?

```sh
qw context list          # shows contexts, endpoints, and LOGGED-IN yes/no
qw context current       # name of the active context
qw whoami                # identity + token expiry of the active context
qw ping                  # endpoint reachable? prints Quickwit version
```

If there is no context, create one (endpoint is the qwproxy URL):

```sh
qw context create prod \
  --endpoint https://qwproxy.internal \
  --issuer https://your-okta.okta.com \
  --client-id <cli-client-id> \
  --default-index core-logs \
  --use
qw login                 # opens a browser (Authorization Code + PKCE)
qw login --device        # headless/SSH box: device-code flow instead
```

`qw login` uses a fixed loopback redirect `http://127.0.0.1:8765/callback`, which
must be registered on the OIDC app (providers like Okta require an exact match —
no wildcard). If login 400s with a `redirect_uri` error, register that exact URI
or override the port with `qw login --redirect-port <port>` (and register the
matching URI). On a headless box use `qw login --device` (no redirect at all). A
confidential app (Okta "Web") also needs its secret: `--client-secret` / `QW_CLIENT_SECRET`.

Switch environments with `qw context use <name>`, or per-command with
`--context <name>` (or the `QW_CONTEXT` env var). If a command fails with
"not logged in", run `qw login`. Manage the config with `qw config path`
(where it lives), `qw config view` (dump it, tokens redacted), and
`qw context delete <name>`.

**Non-interactive / CI (no browser).** In a pipeline or cron, don't run
`qw login`. Set environment variables instead — with `QW_ENDPOINT` plus a
credential you need no config file at all:

- `QW_ENDPOINT` — endpoint base URL (overrides the context)
- `QW_TOKEN` — a static bearer token; skips OIDC entirely
- `QW_CLIENT_SECRET` (+ `QW_ISSUER`, `QW_CLIENT_ID`, `QW_AUDIENCE`) — OIDC
  client-credentials (service account), auto-refreshed

Precedence: `QW_TOKEN` → `QW_CLIENT_SECRET` → cached login tokens.

## Discover before you query

Never guess field names — inspect the schema first (same idea as the
quickwit-mcp `describe_index`):

```sh
qw indexes list                 # all indexes + their timestamp field
qw indexes describe core-logs    # doc counts + min/max timestamp range
qw indexes fields core-logs      # queryable fields and their types (dot paths)
```

`indexes describe` tells you the available time range — useful before picking a
`--since`. `indexes fields` gives the exact field names to use in queries and in
`--fields`.

## Core commands

```sh
qw search  [index] <query>   # find matching log lines (default 20 hits)
qw count   [index] <query>   # just the number of matches
qw histogram [index] <query> # matching volume over time (ASCII bars)
qw tail    [index] <query>   # follow new matches (poll-based; Ctrl-C to stop)
```

`[index]` is optional if the context has a `--default-index`. The index may be a
single id, a comma-list (`a,b`), or a glob (`app-*`).

**Time window** (all of search/count/histogram/tail): Quickwit needs a bound for
efficient split pruning, so `qw` defaults to a recent window (15m for search, 1h
for histogram, 5m for tail). Override with:

- `--since 15m` / `2h` / `1d` — relative to now
- `--from <t>` / `--to <t>` — absolute: epoch, RFC3339, `YYYY-MM-DD`, `now`, or a duration-ago

**Search flags:** `--max-hits N` (default 20), `--offset N` (pagination;
`offset+max-hits` must stay ≤ 10000 — Quickwit's deep-pagination limit),
`--sort-by <field>`, `--search-field <fields>` (default field(s) to match bare
terms against), `--explain` (print the index + JSON query sent).

**Histogram flag:** `--interval 30s|1m|5m|1h` (bucket width).
**Tail flag:** `--interval 2s` (poll cadence).

## Output formats (global flags)

- `-o table` (default) — auto-detects `timestamp/level/service/message` columns, colorizes levels.
- `-o json` — pretty JSON array of hit docs. **Use this when parsing or piping to `jq`.**
- `-o raw` — one line per hit (the message field, or the projected `--fields`).
- `--fields a,b,c.d` — project specific fields (dot paths into nested objects); works in table and raw.
- `--no-color` — disable ANSI colors (also respects `NO_COLOR`).

When gathering data programmatically, prefer `-o json` (or `-o raw --fields ...`)
and pipe to `jq`; the human table format is for interactive reading. Note: hit
counts/latency and status lines go to **stderr**, the actual hits go to
**stdout**, so `qw search ... -o json | jq` stays clean.

- `--jq '<expr>'` — apply a **built-in** jq expression to the hits array (no `jq`
  binary needed; input is the same array `-o json` prints). E.g.
  `qw search core-logs '*' --jq '.[] | {ts: .timestamp, msg: .message}'`.
- `--debug` / `-v` — trace each HTTP request/response to stderr (bearer redacted);
  use it when auth or the proxy misbehaves.

## Query syntax (Quickwit / tantivy)

```
level:ERROR                     field equals value
level:ERROR AND service:api     boolean AND / OR / NOT (uppercase)
message:"connection refused"    phrase match (quoted)
status:[500 TO 599]             numeric/date range
path:/api/*  or  service:app-*  wildcard
_exists_:trace_id               field is present
NOT level:DEBUG                 negation
*                               match everything (still bounded by --since)
```

Match against a default field with `--search-field message`, then bare terms:
`qw search core-logs 'timeout' --search-field message`.
Unsure? The quickwit-mcp `get_query_syntax_help` tool prints the full cheat sheet
(no network call).

## Recipes

```sh
# Errors from one service in the last hour
qw search core-logs 'level:ERROR AND service:payments' --since 1h

# How many 5xx today, and the trend
qw count  core-logs 'status:[500 TO 599]' --since 1d
qw histogram core-logs 'status:[500 TO 599]' --since 1d --interval 1h

# Follow a service live, message only
qw tail core-logs 'service:api' -o raw --fields message

# Find one request across services, as JSON for further processing
qw search 'app-*' 'trace_id:abc123' --since 6h -o json | jq '.[].message'

# Just the fields you care about, as a table
qw search core-logs 'level:WARN' --since 30m --fields timestamp,service,message
```

## Gotchas & guardrails

- **Read-only by design.** The CLI exposes no write verbs, and `qwproxy` rejects
  anything outside the read allowlist (version, list/get/describe indexes,
  search) with `403 … qwproxy is read-only`. You cannot ingest or delete.
- **Time-bounded by default.** An empty window is not "all time" — it's the
  recent default. Widen explicitly with `--since`/`--from` for older data (check
  `qw indexes describe` for the real range first).
- **Deep pagination cap.** `--offset + --max-hits > 10000` makes Quickwit return
  an error; page within that or narrow the query/time window instead.
- **Every query is audited.** Through `qwproxy`, the request envelope *including
  the query string* is recorded to Postgres (never the response body). Assume
  searches are attributable to your identity.
- **Empty results** print `no hits`/`no data in window` to stderr — usually a
  too-narrow `--since` or a wrong field name (re-check `qw indexes fields`).
- **`--explain`** on `search` prints the exact index + JSON body sent to
  Quickwit — use it when a query behaves unexpectedly.
