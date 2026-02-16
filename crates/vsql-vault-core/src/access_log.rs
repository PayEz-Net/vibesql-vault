use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single audit record for any vault operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    pub id: Option<i64>,
    pub entry_id: Option<Uuid>,
    pub purpose: String,
    pub operation: Operation,
    pub caller_app: String,
    pub caller_identity: Option<String>,
    pub granted: bool,
    pub denial_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub client_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Store,
    Retrieve,
    Delete,
    Head,
    List,
    Purge,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Store => write!(f, "store"),
            Operation::Retrieve => write!(f, "retrieve"),
            Operation::Delete => write!(f, "delete"),
            Operation::Head => write!(f, "head"),
            Operation::List => write!(f, "list"),
            Operation::Purge => write!(f, "purge"),
        }
    }
}

impl AccessLogEntry {
    pub fn granted(
        entry_id: Option<Uuid>,
        purpose: &str,
        operation: Operation,
        caller_app: &str,
    ) -> Self {
        Self {
            id: None,
            entry_id,
            purpose: purpose.to_string(),
            operation,
            caller_app: caller_app.to_string(),
            caller_identity: None,
            granted: true,
            denial_reason: None,
            created_at: Utc::now(),
            client_ip: None,
        }
    }

    pub fn denied(
        entry_id: Option<Uuid>,
        purpose: &str,
        operation: Operation,
        caller_app: &str,
        reason: &str,
    ) -> Self {
        Self {
            id: None,
            entry_id,
            purpose: purpose.to_string(),
            operation,
            caller_app: caller_app.to_string(),
            caller_identity: None,
            granted: false,
            denial_reason: Some(reason.to_string()),
            created_at: Utc::now(),
            client_ip: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_granted_log() {
        let id = Uuid::new_v4();
        let log = AccessLogEntry::granted(Some(id), "card", Operation::Retrieve, "payez-api");
        assert!(log.granted);
        assert!(log.denial_reason.is_none());
        assert_eq!(log.purpose, "card");
        assert_eq!(log.entry_id, Some(id));
    }

    #[test]
    fn test_denied_log() {
        let log = AccessLogEntry::denied(
            None,
            "card",
            Operation::Retrieve,
            "rogue-app",
            "not in allowed_apps",
        );
        assert!(!log.granted);
        assert_eq!(log.denial_reason.as_deref(), Some("not in allowed_apps"));
    }

    #[test]
    fn test_operation_display() {
        assert_eq!(Operation::Store.to_string(), "store");
        assert_eq!(Operation::Retrieve.to_string(), "retrieve");
        assert_eq!(Operation::Purge.to_string(), "purge");
    }
}
