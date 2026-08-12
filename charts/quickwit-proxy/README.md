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
| `proxy.oidc.issuer` | OIDC issuer whose tokens are accepted. Discovery is `<issuer>/.well-known/openid-configuration`. |
| `proxy.oidc.clientId` | This deployment's OIDC client id, enforced as the token `aud`. The CLI sends its ID token (aud = client id), so a token minted for another app/env is rejected. **Required** unless `insecureSkipAudience`. |
| `proxy.audit.dsnSecretName` / `dsnSecretKey` | Secret holding the Postgres audit DSN (`QWPROXY_AUDIT_DSN`). Or set `externalSecret.enabled=true` to source it from a secret store. |

The proxy **refuses to start** unless it has an expected audience: set
`proxy.oidc.clientId` (recommended — per-app/env isolation), or the legacy
`proxy.oidc.audience` (an API audience on a custom authorization server), or,
for local/dev only, `proxy.oidc.insecureSkipAudience=true` to accept any
issuer-signed token. Issuer + RS256 JWT signature are always enforced.

## Image

Defaults to the public image `ghcr.io/agarwalvivek29/qwproxy`. Consumers behind
a private registry (e.g. an ECR pull-through cache) override `image.repository`
in their environment values.
