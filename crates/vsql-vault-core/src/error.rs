#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("entry not found: purpose={purpose}, id={id}")]
    NotFound { purpose: String, id: String },

    #[error("entry expired: purpose={purpose}, id={id}")]
    Expired { purpose: String, id: String },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("authentication failed")]
    Unauthorized,

    #[error("purpose not allowed: {0}")]
    Forbidden(String),

    #[error("payload too large: {size} bytes exceeds limit of {limit} bytes")]
    PayloadTooLarge { size: usize, limit: usize },

    #[error("internal error: {0}")]
    Internal(String),
}

impl VaultError {
    pub fn status_code(&self) -> u16 {
        match self {
            VaultError::NotFound { .. } => 404,
            VaultError::Expired { .. } => 404,
            VaultError::Storage(_) => 503,
            VaultError::InvalidInput(_) => 400,
            VaultError::Unauthorized => 401,
            VaultError::Forbidden(_) => 403,
            VaultError::PayloadTooLarge { .. } => 413,
            VaultError::Internal(_) => 500,
        }
    }
}

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

impl From<&VaultError> for ErrorResponse {
    fn from(err: &VaultError) -> Self {
        Self {
            error: err.to_string(),
            code: err.status_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(
            VaultError::NotFound {
                purpose: "card".into(),
                id: "x".into()
            }
            .status_code(),
            404
        );
        assert_eq!(VaultError::Unauthorized.status_code(), 401);
        assert_eq!(VaultError::InvalidInput("x".into()).status_code(), 400);
        assert_eq!(VaultError::Storage("x".into()).status_code(), 503);
        assert_eq!(
            VaultError::PayloadTooLarge {
                size: 100,
                limit: 50
            }
            .status_code(),
            413
        );
    }

    #[test]
    fn test_error_response() {
        let err = VaultError::NotFound {
            purpose: "card".into(),
            id: "abc".into(),
        };
        let resp = ErrorResponse::from(&err);
        assert_eq!(resp.code, 404);
        assert!(resp.error.contains("card"));
        assert!(resp.error.contains("abc"));
    }
}
