use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use vsql_vault_core::access_log::AccessLogEntry;
use vsql_vault_core::access_policy::AccessPolicy;
use vsql_vault_core::entry::{VaultEntry, VaultEntrySummary, VaultMetadata};
use vsql_vault_core::error::VaultError;
use vsql_vault_core::purge::{PurgeLogEntry, PurgeMethod};
use vsql_vault_core::retention::RetentionPolicy;
use vsql_vault_core::storage::VaultStorage;

pub struct PgStorage {
    pool: PgPool,
}

impl PgStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl VaultStorage for PgStorage {
    async fn store(&self, entry: &VaultEntry) -> Result<(), VaultError> {
        let tags = serde_json::to_value(&entry.metadata.tags)
            .map_err(|e| VaultError::InvalidInput(format!("failed to serialize tags: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO vsql_vault.vault_entries
                (id, purpose, encrypted_blob, owner_app, encryption_svc, content_type, tags, created_at, updated_at, expires_at, access_policy)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (purpose, id) DO UPDATE SET
                encrypted_blob = EXCLUDED.encrypted_blob,
                owner_app = EXCLUDED.owner_app,
                encryption_svc = EXCLUDED.encryption_svc,
                content_type = EXCLUDED.content_type,
                tags = EXCLUDED.tags,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at,
                access_policy = EXCLUDED.access_policy
            "#,
        )
        .bind(entry.id)
        .bind(&entry.purpose)
        .bind(&entry.encrypted_blob)
        .bind(&entry.metadata.owner_app)
        .bind(&entry.metadata.encryption_service)
        .bind(&entry.metadata.content_type)
        .bind(&tags)
        .bind(entry.created_at)
        .bind(entry.updated_at)
        .bind(entry.expires_at)
        .bind(&entry.access_policy)
        .execute(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn retrieve(&self, purpose: &str, id: &Uuid) -> Result<Option<VaultEntry>, VaultError> {
        let row = sqlx::query_as::<_, EntryRow>(
            r#"
            SELECT id, purpose, encrypted_blob, owner_app, encryption_svc, content_type, tags,
                   created_at, updated_at, expires_at, access_policy
            FROM vsql_vault.vault_entries
            WHERE purpose = $1 AND id = $2
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(purpose)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(row.map(VaultEntry::from))
    }

    async fn delete(&self, purpose: &str, id: &Uuid) -> Result<bool, VaultError> {
        let result =
            sqlx::query("DELETE FROM vsql_vault.vault_entries WHERE purpose = $1 AND id = $2")
                .bind(purpose)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_by_purpose(
        &self,
        purpose: &str,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<VaultEntrySummary>, u64), VaultError> {
        let total: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM vsql_vault.vault_entries
            WHERE purpose = $1
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(purpose)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        let rows = sqlx::query_as::<_, SummaryRow>(
            r#"
            SELECT id, purpose, owner_app, encryption_svc, content_type, tags, created_at, expires_at
            FROM vsql_vault.vault_entries
            WHERE purpose = $1
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(purpose)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        let summaries = rows.into_iter().map(VaultEntrySummary::from).collect();
        Ok((summaries, total.0 as u64))
    }

    async fn purge_expired(&self) -> Result<u64, VaultError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| VaultError::Storage(e.to_string()))?;

        // Delete expired entries and return them for proof generation
        let deleted_rows = sqlx::query_as::<_, EntryRow>(
            r#"
            DELETE FROM vsql_vault.vault_entries
            WHERE expires_at IS NOT NULL AND expires_at <= NOW()
            RETURNING id, purpose, encrypted_blob, owner_app, encryption_svc, content_type,
                      tags, created_at, updated_at, expires_at, access_policy
            "#,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        let count = deleted_rows.len() as u64;

        // Record purge proof for each deleted entry
        for row in deleted_rows {
            let entry = VaultEntry::from(row);
            let proof_hash = vsql_vault_core::purge::compute_proof_hash(&entry);

            sqlx::query(
                r#"
                INSERT INTO vsql_vault.purge_log
                    (entry_id, purpose, external_id, purge_method, purge_reason, purged_at, purged_by, proof_hash)
                VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)
                "#,
            )
            .bind(entry.id)
            .bind(&entry.purpose)
            .bind(entry.id.to_string())
            .bind("retention-expire")
            .bind("ttl-expired")
            .bind("system/purge-scheduler")
            .bind(proof_hash)
            .execute(&mut *tx)
            .await
            .map_err(|e| VaultError::Storage(format!("failed to record purge proof: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(count)
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| VaultError::Storage(e.to_string()))?;
        Ok(())
    }

    // --- Access Logging ---

    async fn log_access(&self, entry: &AccessLogEntry) -> Result<(), VaultError> {
        sqlx::query(
            r#"
            INSERT INTO vsql_vault.access_log
                (entry_id, purpose, operation, caller_app, caller_identity, granted, denial_reason, created_at, client_ip)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet)
            "#,
        )
        .bind(entry.entry_id)
        .bind(&entry.purpose)
        .bind(entry.operation.to_string())
        .bind(&entry.caller_app)
        .bind(&entry.caller_identity)
        .bind(entry.granted)
        .bind(&entry.denial_reason)
        .bind(entry.created_at)
        .bind(&entry.client_ip)
        .execute(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(format!("failed to log access: {e}")))?;

        Ok(())
    }

    // --- Access Policies ---

    async fn get_access_policy(&self, name: &str) -> Result<Option<AccessPolicy>, VaultError> {
        let row = sqlx::query_as::<_, AccessPolicyRow>(
            "SELECT id, name, description, rules FROM vsql_vault.access_policies WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        match row {
            Some(r) => {
                let rules = serde_json::from_value(r.rules)
                    .map_err(|e| VaultError::Internal(format!("bad policy rules JSON: {e}")))?;
                Ok(Some(AccessPolicy {
                    id: Some(r.id),
                    name: r.name,
                    description: r.description,
                    rules,
                }))
            }
            None => Ok(None),
        }
    }

    async fn upsert_access_policy(&self, policy: &AccessPolicy) -> Result<(), VaultError> {
        let rules = serde_json::to_value(&policy.rules)
            .map_err(|e| VaultError::InvalidInput(format!("bad policy rules: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO vsql_vault.access_policies (name, description, rules, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                rules = EXCLUDED.rules,
                updated_at = NOW()
            "#,
        )
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&rules)
        .execute(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn list_access_policies(&self) -> Result<Vec<AccessPolicy>, VaultError> {
        let rows = sqlx::query_as::<_, AccessPolicyRow>(
            "SELECT id, name, description, rules FROM vsql_vault.access_policies ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                let rules = serde_json::from_value(r.rules)
                    .map_err(|e| VaultError::Internal(format!("bad policy rules JSON: {e}")))?;
                Ok(AccessPolicy {
                    id: Some(r.id),
                    name: r.name,
                    description: r.description,
                    rules,
                })
            })
            .collect()
    }

    // --- Retention Policies ---

    async fn get_retention_policy(
        &self,
        purpose: &str,
    ) -> Result<Option<RetentionPolicy>, VaultError> {
        let row = sqlx::query_as::<_, RetentionPolicyRow>(
            r#"
            SELECT id, purpose, max_retention_days, default_ttl_days, purge_method,
                   require_purge_proof, description
            FROM vsql_vault.retention_policies
            WHERE purpose = $1
            "#,
        )
        .bind(purpose)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(row.map(RetentionPolicy::from))
    }

    async fn upsert_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), VaultError> {
        sqlx::query(
            r#"
            INSERT INTO vsql_vault.retention_policies
                (purpose, max_retention_days, default_ttl_days, purge_method, require_purge_proof, description, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (purpose) DO UPDATE SET
                max_retention_days = EXCLUDED.max_retention_days,
                default_ttl_days = EXCLUDED.default_ttl_days,
                purge_method = EXCLUDED.purge_method,
                require_purge_proof = EXCLUDED.require_purge_proof,
                description = EXCLUDED.description,
                updated_at = NOW()
            "#,
        )
        .bind(&policy.purpose)
        .bind(policy.max_retention_days)
        .bind(policy.default_ttl_days)
        .bind(&policy.purge_method)
        .bind(policy.require_purge_proof)
        .bind(&policy.description)
        .execute(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, VaultError> {
        let rows = sqlx::query_as::<_, RetentionPolicyRow>(
            r#"
            SELECT id, purpose, max_retention_days, default_ttl_days, purge_method,
                   require_purge_proof, description
            FROM vsql_vault.retention_policies
            ORDER BY purpose
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(rows.into_iter().map(RetentionPolicy::from).collect())
    }

    // --- Purge Proof ---

    async fn record_purge(&self, entry: &PurgeLogEntry) -> Result<(), VaultError> {
        sqlx::query(
            r#"
            INSERT INTO vsql_vault.purge_log
                (entry_id, purpose, external_id, purge_method, purge_reason, purged_at, purged_by, proof_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(entry.entry_id)
        .bind(&entry.purpose)
        .bind(&entry.external_id)
        .bind(entry.purge_method.to_string())
        .bind(&entry.purge_reason)
        .bind(entry.purged_at)
        .bind(&entry.purged_by)
        .bind(&entry.proof_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| VaultError::Storage(format!("failed to record purge: {e}")))?;

        Ok(())
    }

    async fn list_purge_log(
        &self,
        purpose: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PurgeLogEntry>, VaultError> {
        let rows = match purpose {
            Some(p) => {
                sqlx::query_as::<_, PurgeLogRow>(
                    r#"
                    SELECT id, entry_id, purpose, external_id, purge_method, purge_reason,
                           purged_at, purged_by, proof_hash
                    FROM vsql_vault.purge_log
                    WHERE purpose = $1
                    ORDER BY purged_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(p)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, PurgeLogRow>(
                    r#"
                    SELECT id, entry_id, purpose, external_id, purge_method, purge_reason,
                           purged_at, purged_by, proof_hash
                    FROM vsql_vault.purge_log
                    ORDER BY purged_at DESC
                    LIMIT $1 OFFSET $2
                    "#,
                )
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| VaultError::Storage(e.to_string()))?;

        Ok(rows.into_iter().map(PurgeLogEntry::from).collect())
    }
}

// --- Row types ---

#[derive(sqlx::FromRow)]
struct EntryRow {
    id: Uuid,
    purpose: String,
    encrypted_blob: Vec<u8>,
    owner_app: String,
    encryption_svc: Option<String>,
    content_type: Option<String>,
    tags: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
    access_policy: String,
}

impl From<EntryRow> for VaultEntry {
    fn from(row: EntryRow) -> Self {
        let tags = serde_json::from_value(row.tags).unwrap_or_default();
        Self {
            id: row.id,
            purpose: row.purpose,
            encrypted_blob: row.encrypted_blob,
            metadata: VaultMetadata {
                owner_app: row.owner_app,
                encryption_service: row.encryption_svc,
                content_type: row.content_type,
                tags,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            access_policy: row.access_policy,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    id: Uuid,
    purpose: String,
    owner_app: String,
    encryption_svc: Option<String>,
    content_type: Option<String>,
    tags: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

impl From<SummaryRow> for VaultEntrySummary {
    fn from(row: SummaryRow) -> Self {
        let tags = serde_json::from_value(row.tags).unwrap_or_default();
        Self {
            id: row.id,
            purpose: row.purpose,
            metadata: VaultMetadata {
                owner_app: row.owner_app,
                encryption_service: row.encryption_svc,
                content_type: row.content_type,
                tags,
            },
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AccessPolicyRow {
    id: i32,
    name: String,
    description: Option<String>,
    rules: serde_json::Value,
}

#[derive(sqlx::FromRow)]
struct RetentionPolicyRow {
    id: i32,
    purpose: String,
    max_retention_days: i32,
    default_ttl_days: Option<i32>,
    purge_method: String,
    require_purge_proof: bool,
    description: Option<String>,
}

impl From<RetentionPolicyRow> for RetentionPolicy {
    fn from(row: RetentionPolicyRow) -> Self {
        Self {
            id: Some(row.id),
            purpose: row.purpose,
            max_retention_days: row.max_retention_days,
            default_ttl_days: row.default_ttl_days,
            purge_method: row.purge_method,
            require_purge_proof: row.require_purge_proof,
            description: row.description,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PurgeLogRow {
    id: i64,
    entry_id: Uuid,
    purpose: String,
    external_id: String,
    purge_method: String,
    purge_reason: String,
    purged_at: chrono::DateTime<Utc>,
    purged_by: String,
    proof_hash: Option<String>,
}

impl From<PurgeLogRow> for PurgeLogEntry {
    fn from(row: PurgeLogRow) -> Self {
        Self {
            id: Some(row.id),
            entry_id: row.entry_id,
            purpose: row.purpose,
            external_id: row.external_id,
            purge_method: PurgeMethod::from_str_lossy(&row.purge_method),
            purge_reason: row.purge_reason,
            purged_at: row.purged_at,
            purged_by: row.purged_by,
            proof_hash: row.proof_hash,
        }
    }
}
