use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub caller_id: String,
    pub allowed_purposes: Option<Vec<String>>,
}

impl AuthContext {
    pub fn can_access_purpose(&self, purpose: &str) -> bool {
        match &self.allowed_purposes {
            None => true,
            Some(purposes) => purposes.iter().any(|p| p == purpose),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrestricted_access() {
        let ctx = AuthContext {
            caller_id: "app".into(),
            allowed_purposes: None,
        };
        assert!(ctx.can_access_purpose("card"));
        assert!(ctx.can_access_purpose("anything"));
    }

    #[test]
    fn test_restricted_access() {
        let ctx = AuthContext {
            caller_id: "app".into(),
            allowed_purposes: Some(vec!["card".into(), "secret".into()]),
        };
        assert!(ctx.can_access_purpose("card"));
        assert!(ctx.can_access_purpose("secret"));
        assert!(!ctx.can_access_purpose("other"));
    }
}
