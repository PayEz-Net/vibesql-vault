-- Phase 2+3: Access logging, access policies, retention policies, purge proof

-- Add missing columns to vault_entries
ALTER TABLE vsql_vault.vault_entries
    ADD COLUMN IF NOT EXISTS algorithm_hint  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS key_ref         VARCHAR(256),
    ADD COLUMN IF NOT EXISTS owner_identity  VARCHAR(256),
    ADD COLUMN IF NOT EXISTS purged_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS purge_method    VARCHAR(32),
    ADD COLUMN IF NOT EXISTS access_policy   VARCHAR(128) NOT NULL DEFAULT 'owner-only';

-- Access log: every store, retrieve, delete is recorded
CREATE TABLE IF NOT EXISTS vsql_vault.access_log (
    id              BIGSERIAL       PRIMARY KEY,
    entry_id        UUID,
    purpose         VARCHAR(64)     NOT NULL,
    operation       VARCHAR(16)     NOT NULL,
    caller_app      VARCHAR(128)    NOT NULL,
    caller_identity VARCHAR(256),
    granted         BOOLEAN         NOT NULL,
    denial_reason   VARCHAR(256),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    client_ip       INET
);

CREATE INDEX IF NOT EXISTS idx_access_log_entry
    ON vsql_vault.access_log (entry_id);
CREATE INDEX IF NOT EXISTS idx_access_log_created
    ON vsql_vault.access_log (created_at);
CREATE INDEX IF NOT EXISTS idx_access_log_caller
    ON vsql_vault.access_log (caller_app, created_at);

-- Access policies: who can store/retrieve/purge
CREATE TABLE IF NOT EXISTS vsql_vault.access_policies (
    id              SERIAL          PRIMARY KEY,
    name            VARCHAR(128)    NOT NULL UNIQUE,
    description     VARCHAR(500),
    rules           JSONB           NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Seed built-in policies
INSERT INTO vsql_vault.access_policies (name, description, rules) VALUES
    ('owner-only',
     'Only the application that stored the entry can retrieve it',
     '{"store":{"allowed_apps":null,"require_identity":false},"retrieve":{"mode":"owner-only","require_identity":false},"purge":{"allowed_apps":null,"require_identity":false}}'
    ),
    ('same-purpose',
     'Any authenticated caller with the same purpose scope can retrieve',
     '{"store":{"allowed_apps":null,"require_identity":false},"retrieve":{"mode":"same-purpose","require_identity":false},"purge":{"allowed_apps":null,"require_identity":false}}'
    ),
    ('open-retrieve',
     'Any authenticated caller can retrieve, store is controlled',
     '{"store":{"allowed_apps":null,"require_identity":false},"retrieve":{"mode":"open","require_identity":false},"purge":{"allowed_apps":null,"require_identity":false}}'
    ),
    ('admin-only',
     'Only admin applications can store, retrieve, or purge',
     '{"store":{"allowed_apps":["vault-admin"],"require_identity":true},"retrieve":{"mode":"restricted","allowed_apps":["vault-admin"],"require_identity":true},"purge":{"allowed_apps":["vault-admin"],"require_identity":true}}'
    )
ON CONFLICT (name) DO NOTHING;

-- Retention policies: per-purpose retention rules
CREATE TABLE IF NOT EXISTS vsql_vault.retention_policies (
    id                  SERIAL          PRIMARY KEY,
    purpose             VARCHAR(64)     NOT NULL UNIQUE,
    max_retention_days  INTEGER         NOT NULL,
    default_ttl_days    INTEGER,
    purge_method        VARCHAR(32)     NOT NULL DEFAULT 'physical-delete',
    require_purge_proof BOOLEAN         NOT NULL DEFAULT TRUE,
    description         VARCHAR(500),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Purge log: proof of deletion for compliance
CREATE TABLE IF NOT EXISTS vsql_vault.purge_log (
    id              BIGSERIAL       PRIMARY KEY,
    entry_id        UUID            NOT NULL,
    purpose         VARCHAR(64)     NOT NULL,
    external_id     VARCHAR(256)    NOT NULL,
    purge_method    VARCHAR(32)     NOT NULL,
    purge_reason    VARCHAR(256)    NOT NULL,
    purged_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    purged_by       VARCHAR(256)    NOT NULL,
    proof_hash      VARCHAR(128)
);

CREATE INDEX IF NOT EXISTS idx_purge_log_entry
    ON vsql_vault.purge_log (entry_id);
CREATE INDEX IF NOT EXISTS idx_purge_log_purged
    ON vsql_vault.purge_log (purged_at);
CREATE INDEX IF NOT EXISTS idx_purge_log_purpose
    ON vsql_vault.purge_log (purpose, purged_at);
