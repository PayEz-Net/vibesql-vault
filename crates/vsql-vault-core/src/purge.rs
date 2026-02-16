use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entry::VaultEntry;

/// A record proving an entry was purged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeLogEntry {
    pub id: Option<i64>,
    pub entry_id: Uuid,
    pub purpose: String,
    pub external_id: String,
    pub purge_method: PurgeMethod,
    pub purge_reason: String,
    pub purged_at: DateTime<Utc>,
    pub purged_by: String,
    pub proof_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PurgeMethod {
    PhysicalDelete,
    CryptoShred,
    RetentionExpire,
}

impl std::fmt::Display for PurgeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeMethod::PhysicalDelete => write!(f, "physical-delete"),
            PurgeMethod::CryptoShred => write!(f, "crypto-shred"),
            PurgeMethod::RetentionExpire => write!(f, "retention-expire"),
        }
    }
}

impl PurgeMethod {
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "crypto-shred" => PurgeMethod::CryptoShred,
            "retention-expire" => PurgeMethod::RetentionExpire,
            _ => PurgeMethod::PhysicalDelete,
        }
    }
}

/// Compute SHA-256 proof hash of an entry at time of purge.
///
/// The hash covers: id, purpose, encrypted_blob (hex), owner_app, created_at.
/// This proves the entry existed with specific content at the time of purge.
pub fn compute_proof_hash(entry: &VaultEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.id.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(entry.purpose.as_bytes());
    hasher.update(b"|");
    hasher.update(&entry.encrypted_blob);
    hasher.update(b"|");
    hasher.update(entry.metadata.owner_app.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.created_at.to_rfc3339().as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{VaultEntry, VaultMetadata};
    use std::collections::HashMap;

    fn test_entry() -> VaultEntry {
        VaultEntry {
            id: Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap(),
            purpose: "card".into(),
            encrypted_blob: vec![1, 2, 3, 4],
            metadata: VaultMetadata {
                owner_app: "payez-api".into(),
                encryption_service: None,
                content_type: None,
                tags: HashMap::new(),
            },
            created_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            updated_at: Utc::now(),
            expires_at: None,
            access_policy: "owner-only".into(),
        }
    }

    #[test]
    fn test_proof_hash_deterministic() {
        let entry = test_entry();
        let hash1 = compute_proof_hash(&entry);
        let hash2 = compute_proof_hash(&entry);
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
        assert_eq!(hash1.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_proof_hash_changes_with_content() {
        let entry1 = test_entry();
        let mut entry2 = test_entry();
        entry2.encrypted_blob = vec![5, 6, 7, 8];
        assert_ne!(compute_proof_hash(&entry1), compute_proof_hash(&entry2));
    }

    #[test]
    fn test_purge_method_display() {
        assert_eq!(PurgeMethod::PhysicalDelete.to_string(), "physical-delete");
        assert_eq!(PurgeMethod::CryptoShred.to_string(), "crypto-shred");
        assert_eq!(PurgeMethod::RetentionExpire.to_string(), "retention-expire");
    }

    #[test]
    fn test_purge_method_from_str() {
        assert_eq!(
            PurgeMethod::from_str_lossy("crypto-shred"),
            PurgeMethod::CryptoShred
        );
        assert_eq!(
            PurgeMethod::from_str_lossy("retention-expire"),
            PurgeMethod::RetentionExpire
        );
        assert_eq!(
            PurgeMethod::from_str_lossy("anything-else"),
            PurgeMethod::PhysicalDelete
        );
    }
}
