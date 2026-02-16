use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// A retention policy for a specific purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub id: Option<i32>,
    pub purpose: String,
    pub max_retention_days: i32,
    pub default_ttl_days: Option<i32>,
    pub purge_method: String,
    pub require_purge_proof: bool,
    pub description: Option<String>,
}

/// Result of validating an expiry against a retention policy.
#[derive(Debug)]
pub enum RetentionDecision {
    /// Expiry is valid (possibly adjusted by default TTL).
    Accept { expires_at: Option<DateTime<Utc>> },
    /// Expiry exceeds max_retention_days.
    Reject { reason: String },
}

impl RetentionPolicy {
    /// Validate and possibly adjust the requested expiry.
    ///
    /// - If `requested_expires_at` is None and `default_ttl_days` is set, apply it.
    /// - If `requested_expires_at` exceeds `max_retention_days` from now, reject.
    pub fn validate_expiry(
        &self,
        requested_expires_at: Option<DateTime<Utc>>,
    ) -> RetentionDecision {
        let now = Utc::now();
        let max_allowed = now + Duration::days(self.max_retention_days as i64);

        match requested_expires_at {
            Some(exp) => {
                if exp > max_allowed {
                    RetentionDecision::Reject {
                        reason: format!(
                            "expires_at {} exceeds max_retention_days ({}) for purpose '{}'. \
                             Latest allowed: {}",
                            exp, self.max_retention_days, self.purpose, max_allowed
                        ),
                    }
                } else {
                    RetentionDecision::Accept {
                        expires_at: Some(exp),
                    }
                }
            }
            None => {
                if let Some(default_days) = self.default_ttl_days {
                    RetentionDecision::Accept {
                        expires_at: Some(now + Duration::days(default_days as i64)),
                    }
                } else {
                    // No expiry requested, no default — accept without expiry
                    RetentionDecision::Accept { expires_at: None }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card_policy() -> RetentionPolicy {
        RetentionPolicy {
            id: None,
            purpose: "card".into(),
            max_retention_days: 365,
            default_ttl_days: Some(90),
            purge_method: "physical-delete".into(),
            require_purge_proof: true,
            description: None,
        }
    }

    #[test]
    fn test_accept_within_max() {
        let policy = card_policy();
        let exp = Utc::now() + Duration::days(100);
        match policy.validate_expiry(Some(exp)) {
            RetentionDecision::Accept { expires_at } => {
                assert_eq!(expires_at, Some(exp));
            }
            RetentionDecision::Reject { reason } => {
                panic!("should accept: {reason}");
            }
        }
    }

    #[test]
    fn test_reject_over_max() {
        let policy = card_policy();
        let exp = Utc::now() + Duration::days(400);
        match policy.validate_expiry(Some(exp)) {
            RetentionDecision::Accept { .. } => {
                panic!("should reject");
            }
            RetentionDecision::Reject { reason } => {
                assert!(reason.contains("max_retention_days"));
            }
        }
    }

    #[test]
    fn test_default_ttl_applied() {
        let policy = card_policy();
        match policy.validate_expiry(None) {
            RetentionDecision::Accept { expires_at } => {
                let exp = expires_at.expect("should have default TTL");
                let diff = exp - Utc::now();
                // Should be ~90 days (allow 1 second tolerance)
                assert!(diff.num_days() >= 89 && diff.num_days() <= 91);
            }
            RetentionDecision::Reject { reason } => {
                panic!("should accept with default TTL: {reason}");
            }
        }
    }

    #[test]
    fn test_no_default_ttl_no_expiry() {
        let policy = RetentionPolicy {
            id: None,
            purpose: "pii".into(),
            max_retention_days: 730,
            default_ttl_days: None,
            purge_method: "physical-delete".into(),
            require_purge_proof: true,
            description: None,
        };
        match policy.validate_expiry(None) {
            RetentionDecision::Accept { expires_at } => {
                assert!(expires_at.is_none());
            }
            RetentionDecision::Reject { reason } => {
                panic!("should accept: {reason}");
            }
        }
    }
}
