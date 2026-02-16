use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    pub purpose: String,
    #[serde(with = "base64_bytes")]
    pub encrypted_blob: Vec<u8>,
    pub metadata: VaultMetadata,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub owner_app: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntrySummary {
    pub id: Uuid,
    pub purpose: String,
    pub metadata: VaultMetadata,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<VaultEntry> for VaultEntrySummary {
    fn from(e: VaultEntry) -> Self {
        Self {
            id: e.id,
            purpose: e.purpose,
            metadata: e.metadata,
            created_at: e.created_at,
            expires_at: e.expires_at,
        }
    }
}

impl VaultEntry {
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() > exp,
            None => false,
        }
    }
}

mod base64_bytes {
    use base64::prelude::*;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_not_expired_when_no_expiry() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            purpose: "card".into(),
            encrypted_blob: vec![1, 2, 3],
            metadata: VaultMetadata {
                owner_app: "test".into(),
                encryption_service: None,
                content_type: None,
                tags: HashMap::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_entry_expired() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            purpose: "card".into(),
            encrypted_blob: vec![1, 2, 3],
            metadata: VaultMetadata {
                owner_app: "test".into(),
                encryption_service: None,
                content_type: None,
                tags: HashMap::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn test_entry_not_expired_future() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            purpose: "card".into(),
            encrypted_blob: vec![1, 2, 3],
            metadata: VaultMetadata {
                owner_app: "test".into(),
                encryption_service: None,
                content_type: None,
                tags: HashMap::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_summary_from_entry() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            purpose: "secret".into(),
            encrypted_blob: vec![99, 100],
            metadata: VaultMetadata {
                owner_app: "app".into(),
                encryption_service: Some("azure-kv".into()),
                content_type: Some("pan".into()),
                tags: HashMap::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };
        let summary = VaultEntrySummary::from(entry.clone());
        assert_eq!(summary.id, entry.id);
        assert_eq!(summary.purpose, "secret");
    }

    #[test]
    fn test_serde_roundtrip() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            purpose: "card".into(),
            encrypted_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            metadata: VaultMetadata {
                owner_app: "test".into(),
                encryption_service: Some("azure-kv".into()),
                content_type: Some("pan".into()),
                tags: [("merchant".into(), "m-1".into())].into(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: VaultEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.encrypted_blob, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decoded.purpose, "card");
        assert!(json.contains("3q2+7w=="));
    }
}
