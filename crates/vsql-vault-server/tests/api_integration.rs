use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware as axum_mw,
    routing::{delete, get, head, put},
    Router,
};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use vsql_vault_core::memory::MemoryStorage;
use vsql_vault_core::retention::RetentionPolicy;

fn build_app(api_key: &str) -> (Router, Arc<vsql_vault_server::state::AppState>) {
    let storage = MemoryStorage::new();
    let state = Arc::new(vsql_vault_server::state::AppState {
        storage: Box::new(storage),
        max_body_bytes: 1_048_576,
    });

    let vault_routes = Router::new()
        .route(
            "/{purpose}/{entry_id}",
            put(vsql_vault_server::api::store_entry),
        )
        .route(
            "/{purpose}/{entry_id}",
            get(vsql_vault_server::api::retrieve_entry),
        )
        .route(
            "/{purpose}/{entry_id}",
            delete(vsql_vault_server::api::delete_entry),
        )
        .route(
            "/{purpose}/{entry_id}",
            head(vsql_vault_server::api::head_entry),
        )
        .route("/{purpose}", get(vsql_vault_server::api::list_entries))
        .layer(axum_mw::from_fn(
            vsql_vault_server::middleware::auth_middleware,
        ));

    let admin_routes = Router::new()
        .route(
            "/retention-policies/{purpose}",
            put(vsql_vault_server::api::upsert_retention_policy),
        )
        .route(
            "/retention-policies",
            get(vsql_vault_server::api::list_retention_policies),
        )
        .route(
            "/access-policies/{name}",
            put(vsql_vault_server::api::upsert_access_policy),
        )
        .route(
            "/access-policies",
            get(vsql_vault_server::api::list_access_policies),
        )
        .route("/purge-log", get(vsql_vault_server::api::list_purge_log))
        .layer(axum_mw::from_fn(
            vsql_vault_server::middleware::auth_middleware,
        ));

    let router = Router::new()
        .nest("/v1/vault", vault_routes)
        .nest("/admin", admin_routes)
        .route("/health", get(vsql_vault_server::health::health))
        .layer(axum::Extension(vsql_vault_server::middleware::ApiKey(
            api_key.to_string(),
        )))
        .with_state(state.clone());

    (router, state)
}

fn store_body(owner: &str) -> String {
    json!({
        "encrypted_blob": "AQID",
        "metadata": {
            "owner_app": owner,
            "encryption_service": "azure-kv",
            "content_type": "pan",
            "tags": { "merchant_id": "m-1" }
        }
    })
    .to_string()
}

fn store_body_with_expiry(owner: &str, expires_at: &str) -> String {
    json!({
        "encrypted_blob": "AQID",
        "metadata": {
            "owner_app": owner,
            "encryption_service": "azure-kv",
            "content_type": "pan",
            "tags": {}
        },
        "expires_at": expires_at
    })
    .to_string()
}

#[tokio::test]
async fn test_health() {
    let (app, _) = build_app("test-key");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_store_and_retrieve() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_store_response_includes_access_policy() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["access_policy"], "owner-only");
    assert_eq!(json["purpose"], "card");
}

#[tokio::test]
async fn test_unauthorized() {
    let (app, _) = build_app("correct-key");
    let id = Uuid::new_v4();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer wrong-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_missing_auth() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_not_found() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_not_found() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_purpose_isolation() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/vault/secret/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_head_entry() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    // Store an entry
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();

    // HEAD returns 200 with metadata headers, no body
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("X-Vault-Created-At").is_some());
    assert!(resp.headers().get("X-Vault-Owner-App").is_some());
}

#[tokio::test]
async fn test_head_not_found() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    let resp = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_retention_policy_enforcement() {
    let (app, state) = build_app("test-key");
    let id = Uuid::new_v4();

    // Create a retention policy: max 30 days for "card" purpose
    let policy = RetentionPolicy {
        id: None,
        purpose: "card".into(),
        max_retention_days: 30,
        default_ttl_days: Some(7),
        purge_method: "physical-delete".into(),
        require_purge_proof: true,
        description: None,
    };
    state
        .storage
        .upsert_retention_policy(&policy)
        .await
        .unwrap();

    // Try to store with expires_at 400 days out — should be rejected (422)
    let far_future = (chrono::Utc::now() + chrono::Duration::days(400)).to_rfc3339();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body_with_expiry("payez", &far_future)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Store without expires_at — should succeed and get default TTL applied
    let id2 = Uuid::new_v4();
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id2}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Should have expires_at set by default TTL
    assert!(json["expires_at"].is_string());
}

#[tokio::test]
async fn test_admin_retention_policies() {
    let (app, _) = build_app("test-key");

    // PUT a retention policy
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/retention-policies/pii")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(
                    json!({
                        "purpose": "pii",
                        "max_retention_days": 730,
                        "default_ttl_days": 365,
                        "purge_method": "physical-delete",
                        "require_purge_proof": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET retention policies
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/retention-policies")
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_admin_purge_log() {
    let (app, _) = build_app("test-key");
    let id = Uuid::new_v4();

    // Store and delete to create a purge log entry
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/vault/card/{id}"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-key")
                .body(Body::from(store_body("payez")))
                .unwrap(),
        )
        .await
        .unwrap();

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/vault/card/{id}"))
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Query purge log
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/purge-log?purpose=card")
                .header("authorization", "Bearer test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0]["proof_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(entries[0]["purge_method"], "physical-delete");
    assert_eq!(entries[0]["purge_reason"], "manual");
}
