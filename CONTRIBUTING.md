# Contributing

Thanks for your interest in improving `quickwit-cli`.

## Development setup

Requires **Go 1.26+**, Docker + Docker Compose.

```sh
git clone https://github.com/agarwalvivek29/quickwit-cli
cd quickwit-cli
make build        # builds ./bin/qw and ./bin/qwproxy
make test         # go vet + go test ./...
make sim-up       # local simulation stack (keycloak + quickwit + postgres + qwproxy)
```

## Before you open a PR

Run the full local gate — CI runs the same thing:

```sh
make check        # fmt-check + vet + lint + test
```

- `gofmt` clean (`make fmt` to fix).
- `go vet ./...` clean.
- `golangci-lint run` clean (installed via `make tools`).
- `go test ./...` green. New behaviour needs a test.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `chore:`,
`docs:`, `test:`, `refactor:`. Keep commits **logically scoped** — one component or concern per
commit, each reviewable on its own.

## Scope & design

The client and proxy are deliberately **read-only** over Quickwit. Admin/ingest is out of scope for
now; if you want it, open an issue first so we can agree on the auth/role model before code.

## Reporting security issues

Please do **not** open a public issue for security problems — see [`SECURITY.md`](./SECURITY.md).
