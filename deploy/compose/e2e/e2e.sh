#!/usr/bin/env sh
# End-to-end smoke test, run from inside the compose network (so keycloak,
# quickwit, qwproxy all resolve by service name). It builds the real qw binary,
# mints a token from Keycloak, and exercises the full path:
#   auth enforcement -> read-only allowlist -> proxied search -> audit in PG.
set -eu

KC="http://keycloak:8080/realms/quickwit"
PROXY="http://qwproxy:9000"
CONFIG=/tmp/qwconfig.yaml
export QW_CONFIG="$CONFIG"

fail() { echo "E2E FAIL: $*" >&2; exit 1; }

echo "e2e: waiting for keycloak ..."
until curl -sf "$KC/.well-known/openid-configuration" >/dev/null 2>&1; do sleep 2; done
echo "e2e: waiting for qwproxy ..."
until curl -sf "$PROXY/health" >/dev/null 2>&1; do sleep 2; done

echo "e2e: minting tokens (resource-owner password grant, sim only)"
TOKRESP=$(curl -sf -XPOST "$KC/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=qw-cli \
  -d username=dev -d password=dev -d scope=openid) || fail "token request failed"
ACCESS=$(printf '%s' "$TOKRESP" | grep -o '"access_token":"[^"]*"' | sed 's/.*:"//; s/"$//')
# The proxy verifies the ID token (aud = qw-cli, the client id); that is the
# credential the CLI presents by default.
TOKEN=$(printf '%s' "$TOKRESP" | grep -o '"id_token":"[^"]*"' | sed 's/.*:"//; s/"$//')
[ -n "$TOKEN" ] || fail "no id_token in response"

cat >"$CONFIG" <<YAML
current-context: local
contexts:
  - name: local
    endpoint: ${PROXY}
    default-index: core-logs
    oidc:
      issuer: ${KC}
      client-id: qw-cli
    auth:
      access-token: "${ACCESS}"
      id-token: "${TOKEN}"
      token-type: Bearer
YAML

echo "e2e: building qw"
go build -o /tmp/qw ./cmd/qw

echo "e2e: negative — no token must be 401"
code=$(curl -s -o /dev/null -w '%{http_code}' "$PROXY/api/v1/version")
[ "$code" = "401" ] || fail "unauthenticated request returned $code, want 401"

echo "e2e: negative — ingest must be blocked (403)"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/api/v1/core-logs/ingest" \
  -H "authorization: Bearer $TOKEN" --data '{}')
[ "$code" = "403" ] || fail "ingest returned $code, want 403"

echo "e2e: qw ping"
/tmp/qw ping || fail "ping"

echo "e2e: qw indexes list"
/tmp/qw indexes list | grep -q core-logs || fail "index core-logs not listed"

echo "e2e: qw indexes fields"
/tmp/qw indexes fields core-logs | grep -q message || fail "field message not found"

echo "e2e: qw count (expect > 0)"
n=$(/tmp/qw count core-logs '*' --since 2h)
[ "$n" -gt 0 ] 2>/dev/null || fail "count was '$n', want > 0"

echo "e2e: qw search level:ERROR (expect hits, json)"
/tmp/qw -o json search core-logs 'level:ERROR' --since 2h | grep -q '"level"' || fail "no ERROR hits"

echo "e2e: qw histogram"
/tmp/qw histogram core-logs '*' --since 2h --interval 1m >/dev/null || fail "histogram"

echo "e2e: allow audit flush"
sleep 2

echo "e2e: proxy reports audited writes"
curl -sf "$PROXY/metrics" | grep '^qwproxy_audit_written_total' | grep -qv ' 0$' \
  || fail "no audit writes recorded in metrics"

echo "E2E OK"
