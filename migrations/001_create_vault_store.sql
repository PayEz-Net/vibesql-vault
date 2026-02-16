CREATE SCHEMA IF NOT EXISTS vsql_vault;

CREATE TABLE vsql_vault.vault_entries (
    id              UUID            NOT NULL,
    purpose         VARCHAR(64)     NOT NULL,
    encrypted_blob  BYTEA           NOT NULL,
    owner_app       VARCHAR(128)    NOT NULL,
    encryption_svc  VARCHAR(128),
    content_type    VARCHAR(64),
    tags            JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,

    PRIMARY KEY (purpose, id)
);

CREATE INDEX idx_vault_entries_expires ON vsql_vault.vault_entries (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE INDEX idx_vault_entries_owner ON vsql_vault.vault_entries (owner_app, purpose);
