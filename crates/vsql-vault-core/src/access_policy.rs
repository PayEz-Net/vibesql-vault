use serde::{Deserialize, Serialize};

/// An access policy governing who can store, retrieve, and purge entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub rules: PolicyRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRules {
    pub store: StoreRule,
    pub retrieve: RetrieveRule,
    pub purge: PurgeRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreRule {
    /// If None, any authenticated app can store.
    pub allowed_apps: Option<Vec<String>>,
    pub require_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveRule {
    /// "owner-only", "same-purpose", "open", "restricted"
    pub mode: String,
    /// Only used when mode is "restricted".
    #[serde(default)]
    pub allowed_apps: Option<Vec<String>>,
    pub require_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeRule {
    pub allowed_apps: Option<Vec<String>>,
    pub require_identity: bool,
}

/// Result of evaluating an access policy.
#[derive(Debug)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

impl AccessPolicy {
    /// Check if the caller is allowed to store under this policy.
    pub fn can_store(&self, caller_app: &str) -> PolicyDecision {
        if let Some(ref allowed) = self.rules.store.allowed_apps {
            if !allowed.iter().any(|a| a == caller_app) {
                return PolicyDecision::Deny(format!(
                    "app '{caller_app}' not in store allowed_apps for policy '{}'",
                    self.name
                ));
            }
        }
        PolicyDecision::Allow
    }

    /// Check if the caller is allowed to retrieve under this policy.
    pub fn can_retrieve(&self, caller_app: &str, owner_app: &str) -> PolicyDecision {
        match self.rules.retrieve.mode.as_str() {
            "owner-only" => {
                if caller_app == owner_app {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny(format!(
                        "policy '{}': owner-only, caller '{caller_app}' is not owner '{owner_app}'",
                        self.name
                    ))
                }
            }
            "same-purpose" => {
                // Any authenticated caller with access to the purpose scope
                PolicyDecision::Allow
            }
            "open" => PolicyDecision::Allow,
            "restricted" => {
                if let Some(ref allowed) = self.rules.retrieve.allowed_apps {
                    if allowed.iter().any(|a| a == caller_app) {
                        PolicyDecision::Allow
                    } else {
                        PolicyDecision::Deny(format!(
                            "app '{caller_app}' not in retrieve allowed_apps for policy '{}'",
                            self.name
                        ))
                    }
                } else {
                    PolicyDecision::Deny(format!(
                        "policy '{}': restricted mode with no allowed_apps configured",
                        self.name
                    ))
                }
            }
            other => PolicyDecision::Deny(format!("unknown retrieve mode: '{other}'")),
        }
    }

    /// Check if the caller is allowed to purge under this policy.
    pub fn can_purge(&self, caller_app: &str) -> PolicyDecision {
        if let Some(ref allowed) = self.rules.purge.allowed_apps {
            if !allowed.iter().any(|a| a == caller_app) {
                return PolicyDecision::Deny(format!(
                    "app '{caller_app}' not in purge allowed_apps for policy '{}'",
                    self.name
                ));
            }
        }
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_only_policy() -> AccessPolicy {
        AccessPolicy {
            id: None,
            name: "owner-only".into(),
            description: None,
            rules: PolicyRules {
                store: StoreRule {
                    allowed_apps: None,
                    require_identity: false,
                },
                retrieve: RetrieveRule {
                    mode: "owner-only".into(),
                    allowed_apps: None,
                    require_identity: false,
                },
                purge: PurgeRule {
                    allowed_apps: None,
                    require_identity: false,
                },
            },
        }
    }

    fn restricted_policy() -> AccessPolicy {
        AccessPolicy {
            id: None,
            name: "payment-service-only".into(),
            description: None,
            rules: PolicyRules {
                store: StoreRule {
                    allowed_apps: Some(vec!["payment-api".into()]),
                    require_identity: true,
                },
                retrieve: RetrieveRule {
                    mode: "restricted".into(),
                    allowed_apps: Some(vec!["payment-api".into(), "refund-service".into()]),
                    require_identity: true,
                },
                purge: PurgeRule {
                    allowed_apps: Some(vec!["vault-admin".into()]),
                    require_identity: true,
                },
            },
        }
    }

    #[test]
    fn test_owner_only_retrieve() {
        let policy = owner_only_policy();
        assert!(policy.can_retrieve("payez-api", "payez-api").is_allowed());
        assert!(!policy.can_retrieve("other-app", "payez-api").is_allowed());
    }

    #[test]
    fn test_owner_only_store_open() {
        let policy = owner_only_policy();
        assert!(policy.can_store("any-app").is_allowed());
    }

    #[test]
    fn test_restricted_store() {
        let policy = restricted_policy();
        assert!(policy.can_store("payment-api").is_allowed());
        assert!(!policy.can_store("rogue-app").is_allowed());
    }

    #[test]
    fn test_restricted_retrieve() {
        let policy = restricted_policy();
        assert!(policy
            .can_retrieve("payment-api", "payment-api")
            .is_allowed());
        assert!(policy
            .can_retrieve("refund-service", "payment-api")
            .is_allowed());
        assert!(!policy.can_retrieve("rogue-app", "payment-api").is_allowed());
    }

    #[test]
    fn test_restricted_purge() {
        let policy = restricted_policy();
        assert!(policy.can_purge("vault-admin").is_allowed());
        assert!(!policy.can_purge("payment-api").is_allowed());
    }

    #[test]
    fn test_open_retrieve() {
        let policy = AccessPolicy {
            id: None,
            name: "open".into(),
            description: None,
            rules: PolicyRules {
                store: StoreRule {
                    allowed_apps: None,
                    require_identity: false,
                },
                retrieve: RetrieveRule {
                    mode: "open".into(),
                    allowed_apps: None,
                    require_identity: false,
                },
                purge: PurgeRule {
                    allowed_apps: None,
                    require_identity: false,
                },
            },
        };
        assert!(policy.can_retrieve("anyone", "doesnt-matter").is_allowed());
    }
}
