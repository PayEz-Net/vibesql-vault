use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vsql_vault_core::access_log::{AccessLogEntry, Operation};
use vsql_vault_core::access_policy::AccessPolicy;
use vsql_vault_core::entry::{VaultEntry, VaultMetadata};
use vsql_vault_core::error::{ErrorResponse, VaultError};
use vsql_vault_core::purge::{self, PurgeLogEntry, PurgeMethod};
use vsql_vault_core::retention::{RetentionDecision, RetentionPolicy};

use crate::state::AppState;

// --- Request / Response Types ---

#[derive(Deserialize)]
pub struct StoreRequest {
    pub encrypted_blob: String,
    pub metadata: StoreMetadata,
    pub expires_at: Option<DateTime<Utc>>,
    pub access_policy: Option<String>,
}

#[derive(Deserialize)]
pub struct StoreMetadata {
    pub owner_app: String,
    pub encryption_service: Option<String>,
    pub content_type: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct StoreResponse {
    pub id: Uuid,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub access_policy: String,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub entries: Vec<ListEntry>,
    pub total: u64,
}

#[derive(Serialize)]
pub struct ListEntry {
    pub id: Uuid,
    pub purpose: String,
    pub metadata: VaultMetadata,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct ListParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    50
}

// --- Handlers ---

pub async fn store_entry(
    State(state): State<Arc<AppState>>,
    Path((purpose, entry_id)): Path<(String, Uuid)>,
    Json(body): Json<StoreRequest>,
) -> impl IntoResponse {
    let caller_app = body.metadata.owner_app.clone();
    let policy_name = body
        .access_policy
        .as_deref()
        .unwrap_or("owner-only")
        .to_string();

    // Decode base64 blob
    let blob = match base64::prelude::BASE64_STANDARD.decode(&body.encrypted_blob) {
        Ok(b) => b,
        Err(e) => {
            log_and_forget(
                &state,
                AccessLogEntry::denied(
                    Some(entry_id),
                    &purpose,
                    Operation::Store,
                    &caller_app,
                    &format!("invalid base64: {e}"),
                ),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid base64 in encrypted_blob: {e}"),
                    "code": 400
                })),
            )
                .into_response();
        }
    };

    // Size check
    if blob.len() > state.max_body_bytes {
        log_and_forget(
            &state,
            AccessLogEntry::denied(
                Some(entry_id),
                &purpose,
                Operation::Store,
                &caller_app,
                "payload too large",
            ),
        )
        .await;
        return vault_error_response(&VaultError::PayloadTooLarge {
            size: blob.len(),
            limit: state.max_body_bytes,
        });
    }

    // Check access policy allows store
    if let Some(policy) = state
        .storage
        .get_access_policy(&policy_name)
        .await
        .ok()
        .flatten()
    {
        let decision = policy.can_store(&caller_app);
        if !decision.is_allowed() {
            let reason = match decision {
                vsql_vault_core::access_policy::PolicyDecision::Deny(r) => r,
                _ => "denied".into(),
            };
            log_and_forget(
                &state,
                AccessLogEntry::denied(
                    Some(entry_id),
                    &purpose,
                    Operation::Store,
                    &caller_app,
                    &reason,
                ),
            )
            .await;
            return vault_error_response(&VaultError::Forbidden(reason));
        }
    }

    // Retention policy enforcement
    let mut effective_expires_at = body.expires_at;
    if let Ok(Some(retention)) = state.storage.get_retention_policy(&purpose).await {
        match retention.validate_expiry(body.expires_at) {
            RetentionDecision::Accept { expires_at } => {
                effective_expires_at = expires_at;
            }
            RetentionDecision::Reject { reason } => {
                log_and_forget(
                    &state,
                    AccessLogEntry::denied(
                        Some(entry_id),
                        &purpose,
                        Operation::Store,
                        &caller_app,
                        &reason,
                    ),
                )
                .await;
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "error": reason,
                        "code": 422
                    })),
                )
                    .into_response();
            }
        }
    }

    let now = Utc::now();
    let entry = VaultEntry {
        id: entry_id,
        purpose: purpose.clone(),
        encrypted_blob: blob,
        metadata: VaultMetadata {
            owner_app: body.metadata.owner_app,
            encryption_service: body.metadata.encryption_service,
            content_type: body.metadata.content_type,
            tags: body.metadata.tags,
        },
        created_at: now,
        updated_at: now,
        expires_at: effective_expires_at,
    };

    match state.storage.store(&entry).await {
        Ok(()) => {
            // Audit log: granted store
            log_and_forget(
                &state,
                AccessLogEntry::granted(Some(entry_id), &purpose, Operation::Store, &caller_app),
            )
            .await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!(StoreResponse {
                    id: entry_id,
                    purpose,
                    created_at: now,
                    expires_at: effective_expires_at,
                    access_policy: policy_name.to_string(),
                })),
            )
                .into_response()
        }
        Err(e) => vault_error_response(&e),
    }
}

pub async fn retrieve_entry(
    State(state): State<Arc<AppState>>,
    Path((purpose, entry_id)): Path<(String, Uuid)>,
) -> impl IntoResponse {
    // For now, caller_app comes from the fact they have the API key.
    // In production, this would come from JWT claims or mTLS cert.
    let caller_app = "authenticated-caller";

    match state.storage.retrieve(&purpose, &entry_id).await {
        Ok(Some(entry)) => {
            // Check access policy
            let policy_name = "owner-only"; // TODO: store access_policy on entry and check here
            if let Ok(Some(policy)) = state.storage.get_access_policy(policy_name).await {
                let decision = policy.can_retrieve(caller_app, &entry.metadata.owner_app);
                if !decision.is_allowed() {
                    let reason = match decision {
                        vsql_vault_core::access_policy::PolicyDecision::Deny(r) => r,
                        _ => "denied".into(),
                    };
                    log_and_forget(
                        &state,
                        AccessLogEntry::denied(
                            Some(entry_id),
                            &purpose,
                            Operation::Retrieve,
                            caller_app,
                            &reason,
                        ),
                    )
                    .await;
                    return vault_error_response(&VaultError::Forbidden(reason));
                }
            }

            // Audit log: granted retrieve
            log_and_forget(
                &state,
                AccessLogEntry::granted(Some(entry_id), &purpose, Operation::Retrieve, caller_app),
            )
            .await;

            (StatusCode::OK, Json(serde_json::to_value(entry).unwrap())).into_response()
        }
        Ok(None) => {
            log_and_forget(
                &state,
                AccessLogEntry::denied(
                    Some(entry_id),
                    &purpose,
                    Operation::Retrieve,
                    caller_app,
                    "not found",
                ),
            )
            .await;
            vault_error_response(&VaultError::NotFound {
                purpose,
                id: entry_id.to_string(),
            })
        }
        Err(e) => vault_error_response(&e),
    }
}

pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    Path((purpose, entry_id)): Path<(String, Uuid)>,
) -> impl IntoResponse {
    let caller_app = "authenticated-caller";

    // Retrieve entry first for purge proof
    let entry_for_proof = state
        .storage
        .retrieve(&purpose, &entry_id)
        .await
        .ok()
        .flatten();

    match state.storage.delete(&purpose, &entry_id).await {
        Ok(true) => {
            // Record purge proof
            if let Some(entry) = entry_for_proof {
                let proof_hash = purge::compute_proof_hash(&entry);
                let purge_entry = PurgeLogEntry {
                    id: None,
                    entry_id,
                    purpose: purpose.clone(),
                    external_id: entry_id.to_string(),
                    purge_method: PurgeMethod::PhysicalDelete,
                    purge_reason: "manual".into(),
                    purged_at: Utc::now(),
                    purged_by: caller_app.into(),
                    proof_hash: Some(proof_hash),
                };
                if let Err(e) = state.storage.record_purge(&purge_entry).await {
                    tracing::error!(error = %e, "failed to record purge proof");
                }
            }

            // Audit log
            log_and_forget(
                &state,
                AccessLogEntry::granted(Some(entry_id), &purpose, Operation::Delete, caller_app),
            )
            .await;

            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            log_and_forget(
                &state,
                AccessLogEntry::denied(
                    Some(entry_id),
                    &purpose,
                    Operation::Delete,
                    caller_app,
                    "not found",
                ),
            )
            .await;
            vault_error_response(&VaultError::NotFound {
                purpose,
                id: entry_id.to_string(),
            })
        }
        Err(e) => vault_error_response(&e),
    }
}

pub async fn head_entry(
    State(state): State<Arc<AppState>>,
    Path((purpose, entry_id)): Path<(String, Uuid)>,
) -> impl IntoResponse {
    let caller_app = "authenticated-caller";

    match state.storage.retrieve(&purpose, &entry_id).await {
        Ok(Some(entry)) => {
            log_and_forget(
                &state,
                AccessLogEntry::granted(Some(entry_id), &purpose, Operation::Head, caller_app),
            )
            .await;

            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                "X-Vault-Created-At",
                entry.created_at.to_rfc3339().parse().unwrap(),
            );
            if let Some(exp) = entry.expires_at {
                headers.insert("X-Vault-Expires-At", exp.to_rfc3339().parse().unwrap());
            }
            headers.insert(
                "X-Vault-Owner-App",
                entry.metadata.owner_app.parse().unwrap(),
            );

            (StatusCode::OK, headers).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn list_entries(
    State(state): State<Arc<AppState>>,
    Path(purpose): Path<String>,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let caller_app = "authenticated-caller";

    match state
        .storage
        .list_by_purpose(&purpose, params.limit, params.offset)
        .await
    {
        Ok((summaries, total)) => {
            log_and_forget(
                &state,
                AccessLogEntry::granted(None, &purpose, Operation::List, caller_app),
            )
            .await;

            let entries: Vec<ListEntry> = summaries
                .into_iter()
                .map(|s| ListEntry {
                    id: s.id,
                    purpose: s.purpose,
                    metadata: s.metadata,
                    created_at: s.created_at,
                    expires_at: s.expires_at,
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!(ListResponse { entries, total })),
            )
                .into_response()
        }
        Err(e) => vault_error_response(&e),
    }
}

// --- Admin: Retention Policies ---

pub async fn list_retention_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.storage.list_retention_policies().await {
        Ok(policies) => (StatusCode::OK, Json(serde_json::json!(policies))).into_response(),
        Err(e) => vault_error_response(&e),
    }
}

pub async fn upsert_retention_policy(
    State(state): State<Arc<AppState>>,
    Path(purpose): Path<String>,
    Json(mut body): Json<RetentionPolicy>,
) -> impl IntoResponse {
    body.purpose = purpose;
    match state.storage.upsert_retention_policy(&body).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!(body))).into_response(),
        Err(e) => vault_error_response(&e),
    }
}

// --- Admin: Access Policies ---

pub async fn list_access_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.storage.list_access_policies().await {
        Ok(policies) => (StatusCode::OK, Json(serde_json::json!(policies))).into_response(),
        Err(e) => vault_error_response(&e),
    }
}

pub async fn upsert_access_policy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(mut body): Json<AccessPolicy>,
) -> impl IntoResponse {
    body.name = name;
    match state.storage.upsert_access_policy(&body).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!(body))).into_response(),
        Err(e) => vault_error_response(&e),
    }
}

// --- Admin: Purge Log ---

#[derive(Deserialize)]
pub struct PurgeLogParams {
    pub purpose: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

pub async fn list_purge_log(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PurgeLogParams>,
) -> impl IntoResponse {
    match state
        .storage
        .list_purge_log(params.purpose.as_deref(), params.limit, params.offset)
        .await
    {
        Ok(entries) => (StatusCode::OK, Json(serde_json::json!(entries))).into_response(),
        Err(e) => vault_error_response(&e),
    }
}

// --- Helpers ---

fn vault_error_response(err: &VaultError) -> axum::response::Response {
    let status =
        StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = ErrorResponse::from(err);
    (status, Json(body)).into_response()
}

/// Fire-and-forget audit log. If logging fails, log the error but don't fail the request.
/// NOTE: In a hardened production build, this would be a blocking audit (fail the operation
/// if audit logging fails). For now we degrade gracefully.
async fn log_and_forget(state: &AppState, entry: AccessLogEntry) {
    if let Err(e) = state.storage.log_access(&entry).await {
        tracing::error!(
            error = %e,
            operation = %entry.operation,
            purpose = %entry.purpose,
            "AUDIT LOG FAILURE - operation proceeded without audit record"
        );
    }
}
