-- qw_api_keys stores long-lived API keys minted by an OIDC-authenticated user.
-- The proxy authorizes a presented key by a local hash lookup — no OIDC round
-- trip — so only the SHA-256 hash of the key is ever stored, never the key
-- itself. A key is valid iff it exists, is unexpired, and is not revoked.

CREATE TABLE IF NOT EXISTS qw_api_keys (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash        text        NOT NULL UNIQUE,   -- sha256(raw key), hex
    prefix          text        NOT NULL,          -- leading chars, for display only
    principal_sub   text        NOT NULL,          -- creator, captured at mint time
    principal_email text,
    description     text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    last_used_at    timestamptz
);

-- Lookups: "list my keys".
CREATE INDEX IF NOT EXISTS qw_api_keys_sub_idx ON qw_api_keys (principal_sub, created_at DESC);
