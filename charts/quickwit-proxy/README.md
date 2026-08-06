# quickwit-proxy Helm chart

Auth (OIDC) + audit reverse proxy in front of Quickwit's read API. Validates a
bearer JWT, enforces a read-only allowlist, and records the request envelope
(including the search query, never response bodies) to Postgres.

## Install

```sh
helm install qwproxy oci://ghcr.io/agarwalvivek29/charts/quickwit-proxy \
  --version 0.1.0 \
  --set proxy.upstream=http://quickwit-searcher.quickwit.svc:7280 \
  --set proxy.oidc.issuer=https://your-oidc-issuer.example.com
```

## Required values

| Key | Description |
|-----|-------------|
| `proxy.upstream` | In-cluster Quickwit searcher REST URL (`:7280`). |
| `proxy.oidc.issuer` | OIDC issuer whose access tokens are accepted. Discovery is `<issuer>/.well-known/openid-configuration`. |
| `proxy.audit.dsnSecretName` / `dsnSecretKey` | Secret holding the Postgres audit DSN (`QWPROXY_AUDIT_DSN`). Or set `externalSecret.enabled=true` to source it from a secret store. |

`proxy.oidc.audience` is optional — leave empty to skip the audience check
(issuer + JWT signature are still enforced).

## Image

Defaults to the public image `ghcr.io/agarwalvivek29/qwproxy`. Consumers behind
a private registry (e.g. an ECR pull-through cache) override `image.repository`
in their environment values.
