use async_trait::async_trait;
use uuid::Uuid;

use crate::access_log::AccessLogEntry;
use crate::access_policy::AccessPolicy;
use crate::entry::{VaultEntry, VaultEntrySummary};
use crate::error::VaultError;
use crate::purge::PurgeLogEntry;
use crate::retention::RetentionPolicy;

#[async_trait]
pub trait VaultStorage: Send + Sync {
    // --- Entry CRUD ---

    async fn store(&self, entry: &VaultEntry) -> Result<(), VaultError>;

    async fn retrieve(&self, purpose: &str, id: &Uuid) -> Result<Option<VaultEntry>, VaultError>;

    async fn delete(&self, purpose: &str, id: &Uuid) -> Result<bool, VaultError>;

    async fn list_by_purpose(
        &self,
        purpose: &str,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<VaultEntrySummary>, u64), VaultError>;

    async fn purge_expired(&self) -> Result<u64, VaultError>;

    async fn health_check(&self) -> Result<(), VaultError>;

    // --- Access Logging ---

    async fn log_access(&self, entry: &AccessLogEntry) -> Result<(), VaultError>;

    // --- Access Policies ---

    async fn get_access_policy(&self, name: &str) -> Result<Option<AccessPolicy>, VaultError>;

    async fn upsert_access_policy(&self, policy: &AccessPolicy) -> Result<(), VaultError>;

    async fn list_access_policies(&self) -> Result<Vec<AccessPolicy>, VaultError>;

    // --- Retention Policies ---

    async fn get_retention_policy(
        &self,
        purpose: &str,
    ) -> Result<Option<RetentionPolicy>, VaultError>;

    async fn upsert_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), VaultError>;

    async fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, VaultError>;

    // --- Purge Proof ---

    async fn record_purge(&self, entry: &PurgeLogEntry) -> Result<(), VaultError>;

    async fn list_purge_log(
        &self,
        purpose: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PurgeLogEntry>, VaultError>;
}
