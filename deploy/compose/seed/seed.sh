#!/usr/bin/env sh
# Wait for Quickwit, create the sample index (idempotent), and ingest ~30 recent
# log lines spanning the last few minutes so `search --since` and `tail` return
# data immediately. Timestamps are unix epoch seconds (a format the index
# mapping accepts), which avoids any date-formatting portability issues.
set -eu

QW="${QW_URL:-http://quickwit:7280}"

echo "seed: waiting for quickwit at $QW ..."
until curl -sf "$QW/api/v1/version" >/dev/null 2>&1; do
  sleep 2
done

if curl -sf "$QW/api/v1/indexes/core-logs" >/dev/null 2>&1; then
  echo "seed: index core-logs already exists"
else
  echo "seed: creating index core-logs"
  curl -sf -XPOST "$QW/api/v1/indexes" \
    -H 'content-type: application/yaml' \
    --data-binary @/seed/index-config.yaml >/dev/null
fi

now=$(date -u +%s)
out=/tmp/logs.ndjson
: >"$out"
i=0
while [ "$i" -lt 30 ]; do
  ts=$((now - i * 20))
  case $((i % 5)) in
    0) lvl=ERROR ;;
    1) lvl=WARN ;;
    *) lvl=INFO ;;
  esac
  svc=checkout
  [ $((i % 2)) -eq 0 ] && svc=payments
  printf '{"timestamp":%s,"level":"%s","service":"%s","message":"request %d handled by %s"}\n' \
    "$ts" "$lvl" "$svc" "$i" "$svc" >>"$out"
  i=$((i + 1))
done

echo "seed: ingesting $(wc -l <"$out") log lines"
curl -sf -XPOST "$QW/api/v1/core-logs/ingest?commit=force" \
  -H 'content-type: application/x-ndjson' \
  --data-binary @"$out" >/dev/null

echo "seed: done"
