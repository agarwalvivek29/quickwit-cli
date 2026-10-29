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

# --- qw upgrade: discover the version the context's server runs ----------------
echo "e2e: /health advertises a version"
curl -sf "$PROXY/health" | grep -q '"version"' || fail "/health has no version field"

echo "e2e: qw upgrade --check reads the context server version"
/tmp/qw upgrade --check 2>&1 | grep -q 'server)' || fail "upgrade --check did not read the server version"

# --- API keys: OIDC mint -> keyless (X-API-Key) use -> revoke ------------------
echo "e2e: apikey create (mint with OIDC)"
CREATE=$(/tmp/qw apikey create --ttl-days 7 --description e2e) || fail "apikey create failed"
KEY=$(printf '%s' "$CREATE" | grep -o 'qw_pat_[0-9a-f]\{64\}' | head -1)
KID=$(printf '%s' "$CREATE" | sed -n 's/^  id:[[:space:]]*//p')
[ -n "$KEY" ] || fail "no api key in create output"
[ -n "$KID" ] || fail "no key id in create output"

echo "e2e: negative — a key cannot mint a key (401)"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/qwproxy/apikeys" -H "X-API-Key: $KEY" --data '{}')
[ "$code" = "401" ] || fail "mint with X-API-Key returned $code, want 401"

echo "e2e: search with X-API-Key works with NO OIDC token (200)"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/api/v1/core-logs/search" \
  -H "X-API-Key: $KEY" -H 'content-type: application/json' --data '{"query":"*","max_hits":1}')
[ "$code" = "200" ] || fail "X-API-Key search returned $code, want 200"

echo "e2e: allowlist still enforced for a key — ingest blocked (403)"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/api/v1/core-logs/ingest" \
  -H "X-API-Key: $KEY" --data '{}')
[ "$code" = "403" ] || fail "ingest with key returned $code, want 403"

echo "e2e: create saved the key to the context; qw now uses it (X-API-Key)"
grep -q 'api-key:' "$CONFIG" || fail "create did not save the key to the context config"
/tmp/qw indexes list | grep -q core-logs || fail "index list via stored api key failed"

echo "e2e: qw apikey list shows the key"
/tmp/qw apikey list | grep -q "$KID" || fail "apikey list missing $KID"

echo "e2e: qw apikey revoke"
/tmp/qw apikey revoke "$KID" || fail "apikey revoke failed"

echo "e2e: revoked key is rejected (401)"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/api/v1/core-logs/search" \
  -H "X-API-Key: $KEY" -H 'content-type: application/json' --data '{"query":"*","max_hits":1}')
[ "$code" = "401" ] || fail "revoked key returned $code, want 401"

# --- service accounts: admin-group gate -> never-expiring key -> disable ------
echo "e2e: non-admin (viewer, no qw-sa-admins group) cannot manage service accounts (403)"
VIEWER=$(curl -sf -XPOST "$KC/protocol/openid-connect/token" -d grant_type=password -d client_id=qw-cli \
  -d username=viewer -d password=viewer -d scope=openid | grep -o '"id_token":"[^"]*"' | sed 's/.*:"//; s/"$//')
[ -n "$VIEWER" ] || fail "no viewer id_token"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/qwproxy/serviceaccounts" \
  -H "Authorization: Bearer $VIEWER" --data '{"name":"nope"}')
[ "$code" = "403" ] || fail "non-admin sa create returned $code, want 403"

echo "e2e: qw sa create (admin via groups claim)"
/tmp/qw sa create e2e-bot --description "e2e agent" || fail "sa create failed"

echo "e2e: qw sa key create --ttl never"
SACREATE=$(/tmp/qw sa key create e2e-bot --ttl never) || fail "sa key create failed"
SAKEY=$(printf '%s' "$SACREATE" | grep -o 'qw_pat_[0-9a-f]\{64\}' | head -1)
SAKID=$(printf '%s' "$SACREATE" | sed -n 's/^  id:[[:space:]]*//p')
[ -n "$SAKEY" ] || fail "no sa key in create output"
printf '%s' "$SACREATE" | grep -q 'expires: never' || fail "sa key is not marked never-expiring"

echo "e2e: disallowed ttl rejected"
if /tmp/qw sa key create e2e-bot --ttl 365d >/dev/null 2>&1; then fail "365d ttl was accepted"; fi

echo "e2e: search with the service-account key (200)"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/api/v1/core-logs/search" \
  -H "X-API-Key: $SAKEY" -H 'content-type: application/json' --data '{"query":"*","max_hits":1}')
[ "$code" = "200" ] || fail "sa key search returned $code, want 200"

echo "e2e: a service-account key cannot manage service accounts (401)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$PROXY/qwproxy/serviceaccounts" -H "X-API-Key: $SAKEY")
[ "$code" = "401" ] || fail "sa key listing service accounts returned $code, want 401"

echo "e2e: qw sa list / key list show the account and key"
/tmp/qw sa list | grep e2e-bot | grep -q active || fail "sa list missing active e2e-bot"
/tmp/qw sa key list e2e-bot | grep "$SAKID" | grep -q never || fail "sa key list missing never-expiring $SAKID"

echo "e2e: qw sa disable kills the key (401)"
/tmp/qw sa disable e2e-bot || fail "sa disable failed"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$PROXY/api/v1/core-logs/search" \
  -H "X-API-Key: $SAKEY" -H 'content-type: application/json' --data '{"query":"*","max_hits":1}')
[ "$code" = "401" ] || fail "key of disabled sa returned $code, want 401"

echo "E2E OK"
