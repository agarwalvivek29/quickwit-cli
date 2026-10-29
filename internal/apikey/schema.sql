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

-- qw_service_accounts are non-human identities (agents, bots) that own API keys
-- in place of a person. Only proxy-configured admin groups can create them or
-- mint their keys; disabling one invalidates all of its keys at once.
CREATE TABLE IF NOT EXISTS qw_service_accounts (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL UNIQUE,
    description      text,
    created_by_sub   text        NOT NULL,
    created_by_email text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    disabled_at      timestamptz,
    disabled_by_sub  text
);

-- A service-account key sets service_account_id (principal_sub is then
-- 'sa:<name>') and records the admin who minted it. Such a key may never expire,
-- so expires_at becomes nullable; personal keys still always carry an expiry.
ALTER TABLE qw_api_keys ADD COLUMN IF NOT EXISTS service_account_id uuid REFERENCES qw_service_accounts (id);
ALTER TABLE qw_api_keys ADD COLUMN IF NOT EXISTS created_by_sub text;
ALTER TABLE qw_api_keys ADD COLUMN IF NOT EXISTS created_by_email text;

-- Guarded so a restart doesn't take an ACCESS EXCLUSIVE lock once applied.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'qw_api_keys' AND column_name = 'expires_at'
                 AND is_nullable = 'NO') THEN
        ALTER TABLE qw_api_keys ALTER COLUMN expires_at DROP NOT NULL;
    END IF;
END $$;

-- Lookups: "list this service account's keys".
CREATE INDEX IF NOT EXISTS qw_api_keys_sa_idx ON qw_api_keys (service_account_id, created_at DESC)
    WHERE service_account_id IS NOT NULL;
