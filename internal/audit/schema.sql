-- qw_audit records the request envelope for every proxied Quickwit call.
-- It stores the request (including the search query_body) but NEVER the
-- response body — that is the whole point, and keeps the table small.
--
-- Range-partitioned by ts (one partition per month); a DEFAULT partition is a
-- safety net so an insert never fails if the month partition has not been
-- created yet. Retention (drop partitions older than 12 months) is handled by
-- the proxy's EnsurePartitions maintenance call.

CREATE TABLE IF NOT EXISTS qw_audit (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    ts              timestamptz NOT NULL DEFAULT now(),
    principal_sub   text,
    principal_email text,
    auth_method     text,
    client_ip       inet,
    user_agent      text,
    cli_version     text,
    method          text,
    path            text,
    index           text,
    query_body      jsonb,
    status_code     integer,
    latency_ms      bigint,
    bytes_out       bigint,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE TABLE IF NOT EXISTS qw_audit_default PARTITION OF qw_audit DEFAULT;

-- Evolve an already-deployed table: how the request authenticated (oidc|api-key).
-- Idempotent, applied at startup by EnsureSchema, so upgrades need no manual step.
ALTER TABLE qw_audit ADD COLUMN IF NOT EXISTS auth_method text;

-- Common lookups: recent activity, and "who searched what".
CREATE INDEX IF NOT EXISTS qw_audit_ts_idx ON qw_audit (ts DESC);
CREATE INDEX IF NOT EXISTS qw_audit_principal_idx ON qw_audit (principal_email, ts DESC);
