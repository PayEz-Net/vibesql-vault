use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use vsql_vault_core::auth::AuthContext;
use vsql_vault_core::error::ErrorResponse;

pub async fn auth_middleware(mut request: Request, next: Next) -> Response {
    let expected_key = match request.extensions().get::<ApiKey>() {
        Some(key) => key.0.clone(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server misconfigured: no API key set".into(),
                    code: 500,
                }),
            )
                .into_response();
        }
    };

    let provided = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if constant_time_eq(token.as_bytes(), expected_key.as_bytes()) => {
            // Extract caller identity from X-Vault-Caller header
            let caller_id = request
                .headers()
                .get("x-vault-caller")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("api-key-holder")
                .to_string();

            request.extensions_mut().insert(AuthContext {
                caller_id,
                allowed_purposes: None,
            });

            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "authentication failed".into(),
                code: 401,
            }),
        )
            .into_response(),
    }
}

#[derive(Clone)]
pub struct ApiKey(pub String);
