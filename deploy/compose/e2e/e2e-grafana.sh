#!/usr/bin/env sh
# Grafana oauthPassThru end-to-end: create a Quickwit datasource (oauthPassThru +
# an API key for the plugin's user-less init call), log in through Keycloak, run
# a query, and assert qwproxy attributed it to the user via the forwarded ID
# token (auth_method = oidc-id-token) while init used the key.
set -eu
apk add -q --no-cache curl postgresql16-client >/dev/null

GF="http://grafana:3000"
KC="http://keycloak:8080/realms/quickwit"
PROXY="http://qwproxy:9000"
JAR=/tmp/jar
fail() { echo "E2E-GRAFANA FAIL: $*" >&2; exit 1; }
psqlq() { PGPASSWORD=qwaudit psql -h postgres -U qwaudit -d qwaudit -tAc "$1"; }

echo "e2e-grafana: waiting for grafana + qwproxy ..."
until curl -sf "$GF/api/health" >/dev/null 2>&1; do sleep 2; done
until curl -sf "$PROXY/health" >/dev/null 2>&1; do sleep 2; done

echo "e2e-grafana: minting the datasource's init API key"
IDT=$(curl -sf -XPOST "$KC/protocol/openid-connect/token" -d grant_type=password -d client_id=qw-cli \
  -d username=dev -d password=dev -d scope=openid | grep -o '"id_token":"[^"]*"' | sed 's/.*:"//; s/"$//')
KEY=$(curl -sf -XPOST "$PROXY/qwproxy/apikeys" -H "Authorization: Bearer $IDT" \
  --data '{"ttl_days":1,"description":"grafana-init"}' | grep -o '"api_key":"[^"]*"' | sed 's/.*:"//; s/"$//')
[ -n "$KEY" ] || fail "could not mint api key"

echo "e2e-grafana: creating datasource (oauthPassThru + X-API-Key)"
curl -s -u admin:admin -XDELETE "$GF/api/datasources/uid/qwproxy" >/dev/null
curl -sf -u admin:admin -H 'content-type: application/json' "$GF/api/datasources" --data @- >/dev/null <<JSON || fail "datasource create"
{"name":"Quickwit via qwproxy","uid":"qwproxy","type":"quickwit-quickwit-datasource","access":"proxy",
 "url":"$PROXY/api/v1",
 "jsonData":{"index":"core-logs","logMessageField":"message","logLevelField":"level","oauthPassThru":true,"httpHeaderName1":"X-API-Key"},
 "secureJsonData":{"httpHeaderValue1":"$KEY"}}
JSON

echo "e2e-grafana: OAuth login (grafana -> keycloak -> grafana)"
auth=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$GF/login/generic_oauth")
action=$(curl -s -c "$JAR" -b "$JAR" "$auth" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
[ -n "$action" ] || fail "no keycloak login form"
cb=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode username=dev --data-urlencode password=dev "$action")
case "$cb" in "$GF/login/generic_oauth"*) ;; *) fail "keycloak did not redirect back: $cb" ;; esac
curl -s -c "$JAR" -b "$JAR" -o /dev/null "$cb"
curl -sf -b "$JAR" "$GF/api/user" | grep -q dev@example.com || fail "grafana session not established"

echo "e2e-grafana: datasource query through qwproxy"
since=$(( $(date +%s) - 7200 ))000
now=$(date +%s)000
resp=$(curl -s -b "$JAR" -H 'content-type: application/json' "$GF/api/ds/query" --data @- <<JSON
{"from":"$since","to":"$now","queries":[{"refId":"A","datasource":{"uid":"qwproxy"},"query":"level:ERROR","metrics":[{"id":"1","type":"count"}],"bucketAggs":[{"id":"2","type":"date_histogram","field":"timestamp","settings":{"interval":"auto"}}],"timeField":"timestamp"}]}
JSON
)
echo "$resp" | grep -q '"status":200' || fail "query failed: $(echo "$resp" | head -c 600)"

echo "e2e-grafana: audit attribution"
sleep 3
user=$(psqlq "select count(*) from qw_audit where auth_method='oidc-id-token' and principal_email='dev@example.com' and path like '%_msearch';")
init=$(psqlq "select count(*) from qw_audit where auth_method='api-key' and path like '/api/v1/indexes%';")
leak=$(psqlq "select count(*) from qw_audit where auth_method='api-key' and path like '%_msearch';")
[ "${user:-0}" -gt 0 ] || fail "no _msearch rows attributed to the user via oidc-id-token"
[ "${init:-0}" -gt 0 ] || fail "plugin init did not authenticate with the api key"
[ "${leak:-0}" -eq 0 ] || fail "$leak user query rows fell back to the api key"
echo "E2E-GRAFANA OK (user _msearch via X-ID-Token: $user, init via api-key: $init)"
