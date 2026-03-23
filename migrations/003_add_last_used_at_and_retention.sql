-- Migration 003: Add last_used_at column + retention harmonization
-- Date: 2026-03-23
-- Author: DotNetPert
-- Spec: vsql-vault Retention Harmonization v1.0.1 (Phase 2A)

-- Add last_used_at column (creation = first use, so default NOW())
ALTER TABLE vsql_vault.vault_entries
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Index for purge sweep: find inactive entries efficiently
CREATE INDEX IF NOT EXISTS idx_vault_entries_last_used
    ON vsql_vault.vault_entries (last_used_at);

-- Backfill existing entries: last_used_at = created_at (conservative: assume last used at creation)
UPDATE vsql_vault.vault_entries
SET last_used_at = created_at
WHERE last_used_at = NOW() AND created_at < NOW() - INTERVAL '1 minute';

-- Update retention policies per spec: card/ach = 540d TTL (18 months from last use), 730d hard ceiling
-- stripe-pm = no expiry (reference only)
INSERT INTO vsql_vault.retention_policies (purpose, max_retention_days, default_ttl_days, purge_method, require_purge_proof, description)
VALUES
    ('card', 730, 540, 'physical-delete', true, 'Credit card vault: 18 months from last use, 2-year hard ceiling'),
    ('ach', 730, 540, 'physical-delete', true, 'ACH vault: 18 months from last use, 2-year hard ceiling'),
    ('stripe-pm', 36500, NULL, 'physical-delete', true, 'Stripe PaymentMethod reference: no expiry (reference only)')
ON CONFLICT (purpose) DO UPDATE SET
    max_retention_days = EXCLUDED.max_retention_days,
    default_ttl_days = EXCLUDED.default_ttl_days,
    description = EXCLUDED.description,
    updated_at = NOW();
