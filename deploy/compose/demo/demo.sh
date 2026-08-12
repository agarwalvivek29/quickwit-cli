#!/usr/bin/env sh
# Narrated walkthrough of the qw CLI driving Quickwit THROUGH qwproxy (auth +
# audit), run from inside the compose network. Produces the transcript captured
# in docs/EXAMPLES.md. Uses a resource-owner-password token to stand in for the
# interactive `qw login` (sim only) so the run is non-interactive.
set -eu

KC="http://keycloak:8080/realms/quickwit"
PROXY="http://qwproxy:9000"
export QW_CONFIG=/tmp/qwconfig.yaml

until curl -sf "$KC/.well-known/openid-configuration" >/dev/null 2>&1; do sleep 2; done
until curl -sf "$PROXY/health" >/dev/null 2>&1; do sleep 2; done

TOKRESP=$(curl -sf -XPOST "$KC/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=qw-cli -d username=dev -d password=dev -d scope=openid)
ACCESS=$(printf '%s' "$TOKRESP" | grep -o '"access_token":"[^"]*"' | sed 's/.*:"//; s/"$//')
# The proxy verifies the ID token (aud = qw-cli); that is the bearer the CLI sends.
TOKEN=$(printf '%s' "$TOKRESP" | grep -o '"id_token":"[^"]*"' | sed 's/.*:"//; s/"$//')

cat >"$QW_CONFIG" <<YAML
current-context: stage
contexts:
  - name: stage
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

cd /src
go build -o /tmp/qw ./cmd/qw 2>/dev/null

run() { printf '\n$ qw %s\n' "$*"; /tmp/qw "$@" 2>&1 || true; }

echo   "############################################################"
echo   "# qw — Quickwit log CLI, driving Quickwit THROUGH qwproxy   #"
echo   "# (every command below is authenticated + audited)         #"
echo   "############################################################"

run context list
run whoami
run ping
run indexes list
run indexes describe core-logs
run indexes fields core-logs
run search core-logs "level:ERROR" --since 2h
run search core-logs "level:ERROR" --since 2h -o json
run search core-logs "service:payments" --fields timestamp,level,service,message --since 2h
run count core-logs "*" --since 2h
run histogram core-logs "*" --since 2h --interval 5m

printf '\n$ qw tail core-logs "*"   (2s sample, then Ctrl-C)\n'
timeout 4 /tmp/qw tail core-logs "*" --since 2h 2>&1 | head -8 || true

echo
echo   "############################################################"
echo   "# The proxy is a READ-ONLY, AUTHENTICATED gate:            #"
echo   "############################################################"
printf '\n$ curl -s -o /dev/null -w "%%{http_code}\\n" %s/api/v1/version   # no token\n' "$PROXY"
curl -s -o /dev/null -w '%{http_code}\n' "$PROXY/api/v1/version"
printf '\n$ curl ... -XPOST %s/api/v1/core-logs/ingest   # write attempt (authed)\n' "$PROXY"
curl -s -o /dev/null -w '%{http_code}\n' -XPOST "$PROXY/api/v1/core-logs/ingest" \
  -H "authorization: Bearer $TOKEN" --data '{}'
echo "(401 = unauthenticated rejected; 403 = write blocked by the read-only allowlist)"
