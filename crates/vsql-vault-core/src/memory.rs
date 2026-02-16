use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::access_log::AccessLogEntry;
use crate::access_policy::AccessPolicy;
use crate::entry::{VaultEntry, VaultEntrySummary};
use crate::error::VaultError;
use crate::purge::PurgeLogEntry;
use crate::retention::RetentionPolicy;
use crate::storage::VaultStorage;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EntryKey {
    purpose: String,
    id: Uuid,
}

#[derive(Debug, Clone)]
pub struct MemoryStorage {
    entries: Arc<RwLock<HashMap<EntryKey, VaultEntry>>>,
    access_log: Arc<RwLock<Vec<AccessLogEntry>>>,
    access_policies: Arc<RwLock<HashMap<String, AccessPolicy>>>,
    retention_policies: Arc<RwLock<HashMap<String, RetentionPolicy>>>,
    purge_log: Arc<RwLock<Vec<PurgeLogEntry>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            access_log: Arc::new(RwLock::new(Vec::new())),
            access_policies: Arc::new(RwLock::new(HashMap::new())),
            retention_policies: Arc::new(RwLock::new(HashMap::new())),
            purge_log: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VaultStorage for MemoryStorage {
    async fn store(&self, entry: &VaultEntry) -> Result<(), VaultError> {
        let key = EntryKey {
            purpose: entry.purpose.clone(),
            id: entry.id,
        };
        let mut entries = self.entries.write().await;
        entries.insert(key, entry.clone());
        Ok(())
    }

    async fn retrieve(&self, purpose: &str, id: &Uuid) -> Result<Option<VaultEntry>, VaultError> {
        let key = EntryKey {
            purpose: purpose.to_string(),
            id: *id,
        };
        let entries = self.entries.read().await;
        match entries.get(&key) {
            Some(entry) if entry.is_expired() => Ok(None),
            Some(entry) => Ok(Some(entry.clone())),
            None => Ok(None),
        }
    }

    async fn delete(&self, purpose: &str, id: &Uuid) -> Result<bool, VaultError> {
        let key = EntryKey {
            purpose: purpose.to_string(),
            id: *id,
        };
        let mut entries = self.entries.write().await;
        Ok(entries.remove(&key).is_some())
    }

    async fn list_by_purpose(
        &self,
        purpose: &str,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<VaultEntrySummary>, u64), VaultError> {
        let entries = self.entries.read().await;
        let now = Utc::now();
        let matching: Vec<_> = entries
            .values()
            .filter(|e| e.purpose == purpose)
            .filter(|e| e.expires_at.is_none_or(|exp| now <= exp))
            .collect();
        let total = matching.len() as u64;
        let page = matching
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .map(VaultEntrySummary::from)
            .collect();
        Ok((page, total))
    }

    async fn purge_expired(&self) -> Result<u64, VaultError> {
        let now = Utc::now();
        let mut entries = self.entries.write().await;

        // Collect expired entries for proof generation before removal
        let expired: Vec<crate::entry::VaultEntry> = entries
            .values()
            .filter(|e| e.expires_at.is_some_and(|exp| now > exp))
            .cloned()
            .collect();

        let count = expired.len() as u64;

        // Generate proof hash and record purge log for each expired entry
        if !expired.is_empty() {
            let mut purge_log = self.purge_log.write().await;
            for entry in &expired {
                let proof_hash = crate::purge::compute_proof_hash(entry);
                purge_log.push(PurgeLogEntry {
                    id: None,
                    entry_id: entry.id,
                    purpose: entry.purpose.clone(),
                    external_id: entry.id.to_string(),
                    purge_method: crate::purge::PurgeMethod::RetentionExpire,
                    purge_reason: "ttl-expired".into(),
                    purged_at: now,
                    purged_by: "system/purge-scheduler".into(),
                    proof_hash: Some(proof_hash),
                });
            }
        }

        // Remove expired entries
        entries.retain(|_, e| e.expires_at.is_none_or(|exp| now <= exp));
        Ok(count)
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        Ok(())
    }

    // --- Access Logging ---

    async fn log_access(&self, entry: &AccessLogEntry) -> Result<(), VaultError> {
        let mut log = self.access_log.write().await;
        log.push(entry.clone());
        Ok(())
    }

    // --- Access Policies ---

    async fn get_access_policy(&self, name: &str) -> Result<Option<AccessPolicy>, VaultError> {
        let policies = self.access_policies.read().await;
        Ok(policies.get(name).cloned())
    }

    async fn upsert_access_policy(&self, policy: &AccessPolicy) -> Result<(), VaultError> {
        let mut policies = self.access_policies.write().await;
        policies.insert(policy.name.clone(), policy.clone());
        Ok(())
    }

    async fn list_access_policies(&self) -> Result<Vec<AccessPolicy>, VaultError> {
        let policies = self.access_policies.read().await;
        Ok(policies.values().cloned().collect())
    }

    // --- Retention Policies ---

    async fn get_retention_policy(
        &self,
        purpose: &str,
    ) -> Result<Option<RetentionPolicy>, VaultError> {
        let policies = self.retention_policies.read().await;
        Ok(policies.get(purpose).cloned())
    }

    async fn upsert_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), VaultError> {
        let mut policies = self.retention_policies.write().await;
        policies.insert(policy.purpose.clone(), policy.clone());
        Ok(())
    }

    async fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, VaultError> {
        let policies = self.retention_policies.read().await;
        Ok(policies.values().cloned().collect())
    }

    // --- Purge Proof ---

    async fn record_purge(&self, entry: &PurgeLogEntry) -> Result<(), VaultError> {
        let mut log = self.purge_log.write().await;
        log.push(entry.clone());
        Ok(())
    }

    async fn list_purge_log(
        &self,
        purpose: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PurgeLogEntry>, VaultError> {
        let log = self.purge_log.read().await;
        let filtered: Vec<_> = log
            .iter()
            .filter(|e| purpose.is_none_or(|p| e.purpose == p))
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_log::Operation;
    use crate::entry::VaultMetadata;
    use std::collections::HashMap as StdHashMap;

    fn make_entry(purpose: &str, expires_at: Option<chrono::DateTime<Utc>>) -> VaultEntry {
        VaultEntry {
            id: Uuid::new_v4(),
            purpose: purpose.into(),
            encrypted_blob: vec![1, 2, 3],
            metadata: VaultMetadata {
                owner_app: "test".into(),
                encryption_service: None,
                content_type: None,
                tags: StdHashMap::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at,
            access_policy: "owner-only".into(),
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = MemoryStorage::new();
        let entry = make_entry("card", None);
        store.store(&entry).await.unwrap();
        let retrieved = store.retrieve("card", &entry.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, entry.id);
    }

    #[tokio::test]
    async fn test_retrieve_nonexistent() {
        let store = MemoryStorage::new();
        let result = store.retrieve("card", &Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_retrieve_expired() {
        let store = MemoryStorage::new();
        let entry = make_entry("card", Some(Utc::now() - chrono::Duration::hours(1)));
        store.store(&entry).await.unwrap();
        let result = store.retrieve("card", &entry.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete() {
        let store = MemoryStorage::new();
        let entry = make_entry("card", None);
        store.store(&entry).await.unwrap();
        assert!(store.delete("card", &entry.id).await.unwrap());
        assert!(!store.delete("card", &entry.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_by_purpose() {
        let store = MemoryStorage::new();
        for _ in 0..5 {
            store.store(&make_entry("card", None)).await.unwrap();
        }
        for _ in 0..3 {
            store.store(&make_entry("secret", None)).await.unwrap();
        }
        let (items, total) = store.list_by_purpose("card", 10, 0).await.unwrap();
        assert_eq!(total, 5);
        assert_eq!(items.len(), 5);

        let (items, total) = store.list_by_purpose("card", 2, 0).await.unwrap();
        assert_eq!(total, 5);
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn test_list_excludes_expired() {
        let store = MemoryStorage::new();
        store.store(&make_entry("card", None)).await.unwrap();
        store
            .store(&make_entry(
                "card",
                Some(Utc::now() - chrono::Duration::hours(1)),
            ))
            .await
            .unwrap();
        let (items, total) = store.list_by_purpose("card", 10, 0).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn test_purge_expired() {
        let store = MemoryStorage::new();
        store.store(&make_entry("card", None)).await.unwrap();
        store
            .store(&make_entry(
                "card",
                Some(Utc::now() - chrono::Duration::hours(1)),
            ))
            .await
            .unwrap();
        store
            .store(&make_entry(
                "secret",
                Some(Utc::now() - chrono::Duration::hours(2)),
            ))
            .await
            .unwrap();
        let purged = store.purge_expired().await.unwrap();
        assert_eq!(purged, 2);
    }

    #[tokio::test]
    async fn test_upsert() {
        let store = MemoryStorage::new();
        let mut entry = make_entry("card", None);
        store.store(&entry).await.unwrap();
        entry.encrypted_blob = vec![9, 8, 7];
        entry.updated_at = Utc::now();
        store.store(&entry).await.unwrap();
        let retrieved = store.retrieve("card", &entry.id).await.unwrap().unwrap();
        assert_eq!(retrieved.encrypted_blob, vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn test_purpose_isolation() {
        let store = MemoryStorage::new();
        let entry = make_entry("card", None);
        store.store(&entry).await.unwrap();
        let result = store.retrieve("secret", &entry.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let store = MemoryStorage::new();
        store.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn test_access_log() {
        let store = MemoryStorage::new();
        let log = AccessLogEntry::granted(Some(Uuid::new_v4()), "card", Operation::Retrieve, "app");
        store.log_access(&log).await.unwrap();
        let logs = store.access_log.read().await;
        assert_eq!(logs.len(), 1);
        assert!(logs[0].granted);
    }

    #[tokio::test]
    async fn test_access_policy_crud() {
        let store = MemoryStorage::new();
        let policy = crate::access_policy::AccessPolicy {
            id: None,
            name: "test-policy".into(),
            description: Some("test".into()),
            rules: crate::access_policy::PolicyRules {
                store: crate::access_policy::StoreRule {
                    allowed_apps: None,
                    require_identity: false,
                },
                retrieve: crate::access_policy::RetrieveRule {
                    mode: "open".into(),
                    allowed_apps: None,
                    require_identity: false,
                },
                purge: crate::access_policy::PurgeRule {
                    allowed_apps: None,
                    require_identity: false,
                },
            },
        };
        store.upsert_access_policy(&policy).await.unwrap();
        let fetched = store.get_access_policy("test-policy").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "test-policy");

        let all = store.list_access_policies().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_retention_policy_crud() {
        let store = MemoryStorage::new();
        let policy = RetentionPolicy {
            id: None,
            purpose: "card".into(),
            max_retention_days: 365,
            default_ttl_days: Some(90),
            purge_method: "physical-delete".into(),
            require_purge_proof: true,
            description: None,
        };
        store.upsert_retention_policy(&policy).await.unwrap();
        let fetched = store.get_retention_policy("card").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().max_retention_days, 365);
    }

    #[tokio::test]
    async fn test_purge_log() {
        let store = MemoryStorage::new();
        let entry = crate::purge::PurgeLogEntry {
            id: None,
            entry_id: Uuid::new_v4(),
            purpose: "card".into(),
            external_id: "payment-123".into(),
            purge_method: crate::purge::PurgeMethod::PhysicalDelete,
            purge_reason: "ttl-expired".into(),
            purged_at: Utc::now(),
            purged_by: "system/purge-scheduler".into(),
            proof_hash: Some("sha256:abc123".into()),
        };
        store.record_purge(&entry).await.unwrap();
        let logs = store.list_purge_log(Some("card"), 10, 0).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].purpose, "card");

        let empty = store.list_purge_log(Some("pii"), 10, 0).await.unwrap();
        assert!(empty.is_empty());
    }
}
