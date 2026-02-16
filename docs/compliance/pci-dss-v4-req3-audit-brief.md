# VibeSQL Vault -- PCI DSS v4.0 Requirement 3 Audit Brief

**Prepared for**: Qualified Security Assessor (QSA)
**Component under assessment**: VibeSQL Vault (`vsql-vault`) — Governed Opaque Storage Vault
**Version**: 0.1.0 (Pre-release, Rev 4 architecture, 56 tests passing)
**Commit**: `bc167038a70da3c58e4282f2966213271ffe1d72`
**Date**: 2026-02-16
**Prepared by**: PayEz-Net / VibeSQL Engineering
**Reviewed by**: QSAPert (PCI DSS SAQ-D Security Review)
**Standard**: PCI DSS v4.0 (March 2022, mandatory March 2025)

> **Attestation**: This document was reviewed against the codebase at the commit hash above.
> Findings, control mappings, and evidence references are accurate as of that commit.
> Any code changes after this commit may invalidate specific findings or control assessments.

---

## 1. Executive Summary

VibeSQL Vault is a **governed opaque storage service** for pre-encrypted data. It does NOT encrypt or decrypt anything. It receives already-encrypted blobs from upstream callers (e.g., PayEz Encryption API backed by Azure Key Vault), stores them with governance controls, and produces compliance evidence.

Think safety deposit box, not locksmith.

**What vsql-vault does:**
- Stores opaque encrypted blobs with metadata (owner, purpose, content_type)
- Enforces per-entry access policies (who can store, retrieve, purge)
- Enforces per-purpose retention policies (max retention, default TTL)
- Logs every operation with granted/denied outcome
- Produces cryptographic purge proof (SHA-256 hash at deletion time)
- Isolates entries by purpose namespace

**What vsql-vault does NOT do:**
- Encrypt or decrypt data
- Manage cryptographic keys
- Perform key rotation, grace periods, or key lifecycle management
- Intercept PostgreSQL wire protocol (no proxy mode)
- Parse or understand encrypted payloads
- Compute blind indexes

Encryption is the **upstream caller's responsibility**. vsql-vault's PCI Req 3 contribution is limited to **storage governance, access control, retention enforcement, and deletion evidence**.

---

## 2. System Description

### 2.1 Architecture

vsql-vault is a Rust HTTP API (axum) backed by PostgreSQL (VibeSQL Micro). Deployed as a hardened pod — FROM scratch Docker image, ~10MB binary, no shell, no attack surface.

```
Upstream Crypto Stack              vsql-vault                     Authorized Consumer
(Azure KV, PayEz Encryption,     (governed storage)              (authorized app)
 any crypto provider)

 plaintext → encrypt → blob  ──►  PUT /v1/vault/{purpose}/{id}
                                   + metadata, ownership,
                                   retention policy, access
                                   contract

                                   GET /v1/vault/{purpose}/{id}  ──►  blob → decrypt → plaintext
                                   (only if caller is
                                    authorized per contract)
```

### 2.2 Storage Schema

Five tables in the `vsql_vault` schema:

| Table | Purpose | PCI Relevance |
|-------|---------|---------------|
| `vault_entries` | Opaque blob storage, PK = `(purpose, id)` | Stored data governance (Req 3.1, 3.3) |
| `access_log` | Every operation logged with granted/denied | Audit trail (Req 3.1, supports Req 10) |
| `access_policies` | Named policy documents with store/retrieve/purge rules | Access control (Req 3.1) |
| `retention_policies` | Per-purpose max_retention_days, default_ttl_days | Data minimization (Req 3.1.1, 3.1.2) |
| `purge_log` | Deletion evidence with SHA-256 proof hash | Purge compliance (Req 3.1.1) |

### 2.3 API Surface

| Method | Path | Purpose |
|--------|------|---------|
| `PUT` | `/v1/vault/{purpose}/{id}` | Store an encrypted blob |
| `GET` | `/v1/vault/{purpose}/{id}` | Retrieve an encrypted blob (if authorized) |
| `DELETE` | `/v1/vault/{purpose}/{id}` | Manually purge an entry |
| `HEAD` | `/v1/vault/{purpose}/{id}` | Check existence + expiry (no blob returned) |
| `GET` | `/v1/vault/{purpose}` | List entries for a purpose (metadata only, no blobs) |
| `PUT` | `/admin/retention-policies/{purpose}` | Create/update retention policy |
| `GET` | `/admin/retention-policies` | List retention policies |
| `PUT` | `/admin/access-policies/{name}` | Create/update access policy |
| `GET` | `/admin/access-policies` | List access policies |
| `GET` | `/admin/purge-log` | Query purge log |
| `GET` | `/health` | Health check |

### 2.4 Authentication

Current implementation uses API key authentication via `Authorization: Bearer <key>` header, validated by `auth_middleware`. Auth context includes `caller_id` and optional `allowed_purposes` for purpose-scoped access.

Spec defines three planned auth methods: JWT (service-to-service), mTLS (highest assurance), and API key (development/simple deployments).

---

## 3. PCI DSS v4.0 Requirement 3 -- Control Mapping

### 3.1 Requirement 3.1 -- Processes and Mechanisms to Protect Stored Account Data

| Sub-Req | Requirement | vsql-vault Control | Evidence | Status |
|---------|-------------|--------------------|----------|--------|
| 3.1.1 | Data retention policies documented, kept up to date, in use, known to affected parties | **Retention policies** enforce per-purpose `max_retention_days` and `default_ttl_days`. Stored in `retention_policies` table. Enforced at store time: requests exceeding `max_retention_days` are rejected (HTTP 422). Default TTL applied when caller omits `expires_at`. Purge sweep deletes expired entries. | `GET /admin/retention-policies`, `purge_log` entries, retention enforcement in `api.rs:170-198` | **Implemented.** Retention enforcement verified by integration test `test_retention_policy_enforcement`. |
| 3.1.2 | Roles and responsibilities for Req 3 activities documented | Access policies define which applications can store, retrieve, and purge entries. Four built-in policies seeded: `owner-only`, `same-purpose`, `open-retrieve`, `admin-only`. Custom policies configurable via admin API. | `GET /admin/access-policies`, `access_policies` table, policy evaluation in `access_policy.rs` | **Implemented.** Policy evaluation tested with 8 unit tests. |

### 3.2 Requirement 3.3 -- Sensitive Authentication Data (SAD) Not Stored After Authorization

| Sub-Req | Requirement | vsql-vault Control | Evidence | Status |
|---------|-------------|--------------------|----------|--------|
| 3.3.1 | SAD not retained after authorization | **Out of scope for vsql-vault.** vsql-vault stores opaque blobs — it does not know what is inside them. SAD prevention is an upstream caller responsibility. The caller must not encrypt and vault SAD post-authorization. | Architecture documentation — vsql-vault cannot inspect blob contents | **N/A — upstream responsibility.** See Section 5 scope boundaries. |
| 3.3.2 | PAN rendered unreadable anywhere stored | **Partially addressed.** vsql-vault stores only pre-encrypted blobs (BYTEA column). It never sees plaintext PAN. All stored values are opaque ciphertext. However, vsql-vault does NOT perform the encryption — it relies on the upstream caller to encrypt before storing. vsql-vault's control is that it **only accepts and returns opaque bytes**, never plaintext. | Direct inspection: `vault_entries.encrypted_blob` column is BYTEA. Entry type `VaultEntry.encrypted_blob: Vec<u8>`. No decryption code exists anywhere in vsql-vault. | **Partial.** vsql-vault ensures stored data remains opaque. Encryption itself is out of scope — assessed at the upstream crypto provider. |
| 3.3.3 | PAN masked when displayed | **Out of scope.** vsql-vault returns encrypted blobs. Display masking is the consuming application's responsibility. | N/A | **N/A** |

### 3.3 Requirement 3.5 -- PAN Secured Wherever Stored

| Sub-Req | Requirement | vsql-vault Control | Evidence | Status |
|---------|-------------|--------------------|----------|--------|
| 3.5.1 | PAN rendered unreadable using strong cryptography | **Out of scope for vsql-vault.** Encryption is performed by the upstream crypto provider (e.g., Azure Key Vault + PayEz Encryption API). vsql-vault stores the result. The `algorithm_hint` and `key_ref` columns in `vault_entries` are **informational only** — vsql-vault does not validate or use them. | Schema: `algorithm_hint VARCHAR(64)`, `key_ref VARCHAR(256)` — both nullable, advisory fields. No crypto code in vsql-vault codebase. | **N/A — upstream responsibility.** Assess encryption strength at the crypto provider. |
| 3.5.1.1 | Hashes used to render PAN unreadable are keyed | **Not applicable.** vsql-vault does not hash PAN. The only hash it computes is SHA-256 purge proof (hash of the full entry record at deletion time, for compliance evidence — not for PAN rendering). | `purge.rs:54-67` — `compute_proof_hash()` hashes `id|purpose|encrypted_blob|owner_app|created_at` | **N/A** |
| 3.5.1.2 | If disk-level encryption used, logical access controls applied | **Not directly applicable.** vsql-vault provides logical access control over stored encrypted blobs via access policies. Disk-level encryption of the PostgreSQL data directory is an infrastructure concern. | Access policy enforcement, purpose isolation via composite PK `(purpose, id)` | **Partial — infrastructure responsibility for disk encryption.** |

### 3.4 Requirement 3.6 -- Cryptographic Keys Secured

| Sub-Req | Requirement | vsql-vault Control | Evidence | Status |
|---------|-------------|--------------------|----------|--------|
| 3.6.1 | Procedures to protect cryptographic keys | **Out of scope.** vsql-vault does not hold, manage, or access cryptographic keys. The `key_ref` column is informational only. Key management is the upstream crypto provider's responsibility. | No `KeyProvider` trait, no key cache, no key material in vsql-vault. Zero crypto imports (no `aes-gcm`, no `ring`, no `rustls` for key ops). | **N/A — assess at crypto provider.** |
| 3.6.1.1–3.6.1.4 | Key generation, distribution, storage, rotation | **All out of scope.** vsql-vault tracks `key_ref` per entry for informational purposes (enables compliance reporting on key staleness) but does not generate, distribute, store, or rotate keys. | `key_ref` column added in migration `002`, not used in any application logic | **N/A** |

### 3.5 Requirement 3.7 -- Key Management Policies

| Sub-Req | Requirement | vsql-vault Control | Evidence | Status |
|---------|-------------|--------------------|----------|--------|
| 3.7.1 | Key management policies documented | **Out of scope.** Key management policy documentation is the responsibility of the crypto provider operator. vsql-vault's compliance report can surface key staleness data via `key_ref` grouping (planned, not yet implemented). | Spec Section 6.1 defines planned compliance report | **N/A — upstream responsibility.** |
| 3.7.2 | Key management procedures include processes for key activities | **Out of scope.** | N/A | **N/A** |
| 3.7.3 | Access to cleartext cryptographic keys restricted | **Out of scope.** vsql-vault never possesses cleartext key material. | Source code review — no key material variables, no key imports | **N/A** |

---

## 4. Governance Controls -- Detailed Assessment

These are the controls vsql-vault **does** provide. They don't map cleanly to a single Req 3 sub-requirement but collectively support Req 3.1 (data retention, access governance) and provide evidence for the broader PCI assessment.

### 4.1 Access Policy Enforcement

**PCI Relevance**: Req 3.1.2 (roles and responsibilities), supports Req 7 (restrict access)

**What exists:**
- Four built-in policies: `owner-only` (default), `same-purpose`, `open-retrieve`, `admin-only`
- Policy rules are structured JSONB with separate `store`, `retrieve`, and `purge` rule blocks
- Each rule block can restrict by `allowed_apps` list and `require_identity` flag
- Retrieve modes: `owner-only` (caller must be owner_app), `same-purpose` (any caller in purpose scope), `open` (any authenticated), `restricted` (explicit allowlist)
- Policy evaluation returns `Allow` or `Deny(reason)` — denial reason logged to access_log

**Evidence source**: `access_policy.rs` — full policy engine with 8 unit tests covering all modes

### 4.2 Retention Policy Enforcement

**PCI Relevance**: Req 3.1.1 (data retention policies)

**What exists:**
- Per-purpose retention policies with `max_retention_days` and optional `default_ttl_days`
- **Strict enforcement at store time**: if `expires_at` exceeds `max_retention_days`, request rejected (HTTP 422)
- **Default TTL**: if caller omits `expires_at` and policy has `default_ttl_days`, TTL is applied automatically
- **Purge sweep**: `purge_expired()` deletes entries where `expires_at <= NOW()`
- **Retrieve-time check**: expired entries filtered by SQL `WHERE expires_at IS NULL OR expires_at > NOW()`
- Configurable `purge_method` per policy: `physical-delete`, `crypto-shred`, `retention-expire`

**Evidence source**: `retention.rs` — `validate_expiry()` with 4 unit tests; `api.rs:170-198` store-time enforcement; integration test `test_retention_policy_enforcement`

### 4.3 Purge Proof (Deletion Evidence)

**PCI Relevance**: Req 3.1.1 (prove data was destroyed per policy)

**What exists:**
- On manual delete: entry retrieved, SHA-256 hash computed over `id|purpose|encrypted_blob|owner_app|created_at`, recorded in `purge_log` with `purge_method`, `purge_reason`, `purged_by`, `purged_at`
- Hash format: `sha256:{64 hex chars}` (deterministic, verified by unit test)
- Purge log is append-only — records persist even after the entry is physically deleted from `vault_entries`
- Purge log queryable via `GET /admin/purge-log?purpose={purpose}`

**Evidence source**: `purge.rs:54-67` — `compute_proof_hash()`; `api.rs:311-338` delete handler; integration test `test_admin_purge_log` (verifies hash starts with `sha256:`)

### 4.4 Audit Trail

**PCI Relevance**: Req 3.1 (governance), supports Req 10 (logging)

**What exists:**
- Every operation logged to `access_log`: store, retrieve, delete, head, list
- Log fields: `entry_id`, `purpose`, `operation`, `caller_app`, `caller_identity`, `granted` (boolean), `denial_reason`, `created_at`, `client_ip`
- Both successful and denied operations are logged
- Denied operations include the specific denial reason

**Evidence source**: `access_log.rs` — `AccessLogEntry::granted()` and `AccessLogEntry::denied()` constructors; `pg_storage.rs:153-175` — `log_access()` SQL; audit logging verified through all integration tests

### 4.5 Purpose Isolation

**PCI Relevance**: Req 3.1 (scope containment)

**What exists:**
- Entries are keyed by composite PK `(purpose, id)`
- A `card` entry cannot be retrieved via the `pii` namespace — different purpose = different entry space
- Verified by integration test `test_purpose_isolation`

---

## 5. Scope Boundaries

### 5.1 In Scope (vsql-vault provides this control)

| Control | vsql-vault Component |
|---------|---------------------|
| Governed storage of pre-encrypted blobs | `vault_entries` table, store/retrieve API |
| Per-entry access control | Access policies, `can_store()` / `can_retrieve()` / `can_purge()` |
| Retention enforcement (max retention, default TTL) | Retention policies, store-time validation |
| Purge with cryptographic proof | `purge_log` with SHA-256 hash |
| Operation audit trail (granted/denied) | `access_log` table |
| Purpose-scoped namespace isolation | Composite PK `(purpose, id)` |
| Authentication at API boundary | Auth middleware (API key, planned JWT + mTLS) |

### 5.2 Out of Scope (upstream or infrastructure responsibility)

| Control | Responsible Party | PCI Req | Notes |
|---------|-------------------|---------|-------|
| Encryption of data (PAN, PII, etc.) | Upstream crypto provider (e.g., PayEz Encryption API + Azure KV) | 3.3.2, 3.5.1 | vsql-vault never sees plaintext |
| Cryptographic key management | Upstream crypto provider | 3.6, 3.7 | vsql-vault has no key material |
| Key rotation and cryptoperiod enforcement | Upstream crypto provider | 3.6.1.4 | `key_ref` field is informational only |
| SAD (CVV, track data, PIN) not stored | Application layer | 3.3.1 | vsql-vault cannot inspect blob contents |
| PAN masking on display | Application layer | 3.3.3 | vsql-vault returns encrypted blobs |
| Disk-level encryption of PostgreSQL data directory | Infrastructure / VibeSQL Micro deployment | 3.5.1.2 | Recommended but not enforced by vsql-vault |
| Network segmentation (CDE isolation) | Infrastructure | Req 1 | Spec mandates protected segment deployment |
| TLS for API transport | Deployment configuration | Req 4 | Spec requires TLS on port 8443 |

### 5.3 Critical Scoping Note for Assessor

vsql-vault's scope within PCI Req 3 is **storage governance only**. It satisfies Req 3.1 (retention policies, access control, audit) and provides supporting evidence for Req 3.3.2 (stored data is opaque ciphertext). But the core encryption controls (Req 3.5, 3.6, 3.7) must be assessed at the upstream crypto provider.

If the assessor determines that vsql-vault's storage of encrypted blobs places it in the CDE, then the following apply:
- vsql-vault's network segment, container security, and access controls are in scope
- The encrypted blobs in `vault_entries.encrypted_blob` must be verified as strong ciphertext at the provider level
- vsql-vault's inability to decrypt is itself a scope-reduction control — it cannot leak what it cannot read

---

## 6. Findings from Code Review

The following findings were identified during code review of the current implementation. These are ranked by PCI impact.

### Finding 1: Audit Logging Is Fire-and-Forget

**PCI Requirement**: 3.1.1 (governance), 10.2 (audit trails)
**Severity**: High
**Evidence Observed**: `api.rs:522-531` — `log_and_forget()` function catches audit log write failures, logs an error, but allows the vault operation to proceed without an audit record.

```rust
async fn log_and_forget(state: &AppState, entry: AccessLogEntry) {
    if let Err(e) = state.storage.log_access(&entry).await {
        tracing::error!("AUDIT LOG FAILURE - operation proceeded without audit record");
    }
}
```

**Risk**: A vault store or retrieve can succeed without a corresponding audit record. An attacker who can cause audit log writes to fail (e.g., by filling the `access_log` table or causing DB connection exhaustion) could operate against the vault without leaving evidence.

**Recommendation**: For PCI compliance, audit logging should be **blocking** — if the audit log write fails, the vault operation should fail. The code itself acknowledges this in the comment: *"In a hardened production build, this would be a blocking audit."*

**Compensating Control**: Application-level tracing (`tracing::error!`) captures the failure, but only if log aggregation is configured and monitored.

---

### Finding 2: Caller Identity Not Extracted from Auth Context on Retrieve/Delete/Head/List

**PCI Requirement**: 3.1.2 (roles and responsibilities), 10.2.1 (user identification in logs)
**Severity**: High
**Evidence Observed**: `api.rs:247`, `api.rs:309`, `api.rs:375`, `api.rs:409` — `caller_app` is hardcoded to `"authenticated-caller"` for all non-store operations.

```rust
let caller_app = "authenticated-caller"; // retrieve, delete, head, list
```

**Risk**: Access log entries for retrieve, delete, head, and list operations do not identify the actual caller. All operations appear as the same generic identity, defeating the purpose of the audit trail. Access policies that check caller identity (e.g., `owner-only` retrieve) cannot function correctly because the caller is never the `owner_app` unless they happen to be named `"authenticated-caller"`.

**Recommendation**: Extract `caller_app` (and ideally `caller_identity`) from the authenticated request context (JWT claims, mTLS cert subject, or API key identity) and propagate through all handlers.

**Compensating Control**: None effective. The access log is materially incomplete for non-store operations.

---

### Finding 3: Access Policy Not Retrieved from Entry on Retrieve

**PCI Requirement**: 3.1.2 (access control enforcement)
**Severity**: High
**Evidence Observed**: `api.rs:253` — retrieve handler hardcodes `policy_name = "owner-only"` with a TODO comment, ignoring the `access_policy` column stored on the entry.

```rust
let policy_name = "owner-only"; // TODO: store access_policy on entry and check here
```

**Risk**: Even if an entry was stored with a custom access policy (e.g., `payment-service-only`), retrieval always evaluates against the default `owner-only` policy. Custom access contracts are effectively unenforced on retrieve.

**Recommendation**: Read the `access_policy` value from the stored entry and evaluate against that policy. The column exists in the schema (`access_policy VARCHAR(128) NOT NULL DEFAULT 'owner-only'`) but is not queried back during retrieve.

**Compensating Control**: The default `owner-only` policy is the most restrictive built-in policy, so the fail-open direction is conservative. But entries explicitly assigned less restrictive policies (e.g., `same-purpose`) would behave more restrictively than intended.

---

### Finding 4: Purge Sweep Does Not Generate Purge Proof

**PCI Requirement**: 3.1.1 (prove data was destroyed per policy)
**Severity**: Medium
**Evidence Observed**: `pg_storage.rs:132-141` — `purge_expired()` performs a bulk `DELETE` without recording individual purge proof entries.

```rust
async fn purge_expired(&self) -> Result<u64, VaultError> {
    let result = sqlx::query(
        "DELETE FROM vsql_vault.vault_entries WHERE expires_at IS NOT NULL AND expires_at <= NOW()",
    ).execute(&self.pool).await...
```

**Risk**: Entries purged by the scheduled sweep leave no record in `purge_log`. Only manual deletes (via `DELETE /v1/vault/{purpose}/{id}`) generate purge proof. A QSA asking "prove entry X was destroyed per retention policy" would find no evidence for sweep-purged entries.

**Recommendation**: Before bulk delete, select the entries, compute proof hashes, write to `purge_log`, then delete. Process in batches per the spec's `sweep_batch_size` configuration.

**Compensating Control**: Manual deletes do produce proof. But automated retention-based purging — the primary compliance mechanism — does not.

---

### Finding 5: No TLS Configuration in Current Build

**PCI Requirement**: Req 4.2.1 (strong cryptography for transmission)
**Severity**: Medium (pre-release, but must be resolved before production)
**Evidence Observed**: Server configuration in spec defines TLS on port 8443 with cert/key paths, but the current server implementation does not appear to configure TLS termination. Integration tests connect over plain HTTP.

**Risk**: In production without TLS, encrypted blobs transit in cleartext over the network. While the blobs are encrypted, the metadata (purpose, owner_app, tags) is not — and metadata leakage is a PCI concern.

**Recommendation**: Implement TLS termination in the Rust server (axum-server with rustls) or deploy behind a TLS-terminating reverse proxy with documented configuration. Verify before production deployment.

**Compensating Control**: Deployment behind a TLS-terminating load balancer (e.g., NGINX, Envoy, cloud LB) with end-to-end TLS within the pod.

---

### Finding 6: Retention Policy Not Enforced When No Policy Exists for Purpose

**PCI Requirement**: 3.1.1 (retention policies)
**Severity**: Low
**Evidence Observed**: `api.rs:171` — retention enforcement is conditional: `if let Ok(Some(retention)) = ...`. If no retention policy exists for a purpose, entries can be stored without any expiry, indefinitely.

**Risk**: A caller can store encrypted blobs under a purpose that has no retention policy, and those entries will persist forever — violating data minimization principles.

**Recommendation**: Either require a retention policy for every purpose (reject stores to purposes without a policy) or enforce a system-wide default maximum retention.

**Compensating Control**: Admin discipline to create retention policies for all purposes before deploying to production.

---

## 7. Compliance Evidence Sources

vsql-vault produces the following evidence artifacts:

| Evidence | Source | What It Proves |
|----------|--------|----------------|
| Retention policies | `GET /admin/retention-policies` | Per-purpose data retention limits are defined and enforced |
| Access policies | `GET /admin/access-policies` | Per-entry access contracts governing store/retrieve/purge |
| Access log | `access_log` table | Every operation was authorized or denied, with reason |
| Purge log | `GET /admin/purge-log` | Entries were destroyed with SHA-256 proof hash |
| Purpose isolation | Composite PK `(purpose, id)` | Cross-purpose access is structurally impossible |
| Retention enforcement | HTTP 422 on store | Entries exceeding max retention are rejected at ingestion |
| Default TTL application | Store response `expires_at` | Entries receive automatic expiry when policy defines default |

### 7.1 Planned Evidence (Not Yet Implemented)

| Evidence | Endpoint | Status |
|----------|----------|--------|
| Compliance report | `GET /compliance/report` | Spec Section 6.2. Not yet implemented. |
| CryptAply integration | Evidence push | Spec Section 6.3. Not yet implemented. |
| Key staleness report | Compliance report | Requires `key_ref` grouping. Advisory only. |
| Purge sweep status | `GET /admin/purge/sweep/status` | Not yet implemented. |

---

## 8. Assessor Checklist

For the QSA's use during assessment:

### Storage Governance (vsql-vault controls)
- [ ] Verify `vault_entries.encrypted_blob` column contains opaque binary data (BYTEA), not cleartext
- [ ] Verify no decryption code exists in vsql-vault codebase (`cargo doc --document-private-items`, search for crypto imports)
- [ ] Verify retention policies exist for all active purposes (`GET /admin/retention-policies`)
- [ ] Verify retention enforcement: attempt to store an entry exceeding `max_retention_days` → expect HTTP 422
- [ ] Verify default TTL: store an entry without `expires_at` under a purpose with `default_ttl_days` → expect `expires_at` in response
- [ ] Verify purge proof: delete an entry, query `GET /admin/purge-log` → expect `proof_hash` starting with `sha256:`
- [ ] Verify access policies are seeded (`GET /admin/access-policies` returns `owner-only`, `same-purpose`, `open-retrieve`, `admin-only`)
- [ ] Verify purpose isolation: store under purpose `card`, retrieve under purpose `pii` with same ID → expect 404
- [ ] Verify authentication: request without `Authorization` header → expect 401
- [ ] Verify authentication: request with wrong key → expect 401

### Findings Remediation (must-fix before production)
- [ ] **Finding 1**: Audit logging is blocking (operations fail if audit write fails)
- [ ] **Finding 2**: Caller identity extracted from auth context for all operations (not hardcoded)
- [ ] **Finding 3**: Access policy retrieved from stored entry on retrieve (not hardcoded to `owner-only`)
- [ ] **Finding 4**: Purge sweep generates individual purge proof entries before deleting
- [ ] **Finding 5**: TLS enabled on vault API port (or TLS-terminating proxy documented)
- [ ] **Finding 6**: System-wide default retention or mandatory per-purpose retention policy

### Upstream Verification (not vsql-vault's scope, but required for Req 3)
- [ ] Verify upstream crypto provider uses strong cryptography (AES-256, RSA-4096, etc.)
- [ ] Verify upstream key management: rotation, access control, FIPS certification
- [ ] Verify upstream does not send plaintext to vsql-vault
- [ ] Verify application layer prevents SAD (CVV, track data, PIN) from being encrypted and vaulted

---

## 9. Technology Stack

| Component | Technology | Security Relevance |
|-----------|------------|-------------------|
| Language | Rust (2021 edition) | Memory safety without GC |
| HTTP framework | axum | Minimal, async, well-audited |
| Database | PostgreSQL (VibeSQL Micro) | Pod-internal only, not exposed |
| Auth | API key (current), JWT + mTLS (planned) | See Finding 2 |
| Hashing | SHA-256 (`sha2` crate) | Purge proof only — not for encryption |
| Serialization | serde + serde_json | Typed deserialization, no parsing vulnerabilities |
| Container | FROM scratch Docker | No shell, no package manager, minimal attack surface |

---

## 10. Contact Information

> **ACTION REQUIRED**: All contacts must be filled in before the QSA assessment.

| Role | Contact |
|------|---------|
| Engineering lead | [To be provided before assessment] |
| Security / compliance | [To be provided before assessment] |
| Upstream crypto provider admin | [To be provided before assessment] |
| Infrastructure / network segmentation | [To be provided before assessment] |

---

## Appendix A: Referenced Standards

- PCI DSS v4.0 (March 2022)
- NIST SP 800-57 Part 1: Recommendation for Key Management (upstream responsibility)

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| PAN | Primary Account Number — the card number (Req 3 primary concern) |
| SAD | Sensitive Authentication Data — CVV, track data, PIN (must not be stored post-auth) |
| Purge proof | SHA-256 hash of vault entry at deletion time, proving data existed and was destroyed |
| Purpose | Namespace for entry isolation (e.g., `card`, `pii`, `credential`) |
| Access policy | Named contract defining which apps can store, retrieve, and purge entries |
| Retention policy | Per-purpose configuration defining max retention days and default TTL |
| Opaque blob | Encrypted data that vsql-vault stores without parsing or understanding |
| CryptAply | Planned compliance evidence and governance platform (not yet integrated) |

## Appendix C: What Was Removed from Previous Audit

The previous audit brief (dated 2026-02-16, Rev 1-3 architecture) described vsql-vault as a **field-level encryption engine**. The following controls from that document are **entirely out of scope** in the Rev 4 architecture and have been removed:

- AES-256-GCM encryption/decryption engine
- Key lifecycle management (rotation, grace periods, retirement)
- Key provider abstraction (Azure KV, HC Vault, KMS integration)
- Key wrapping (RSA-OAEP KEK/DEK)
- Key material handling (zeroize, mlock, cache TTL, cache flush)
- Blind index key management (HMAC-SHA256)
- Proxy mode (PostgreSQL wire protocol interception)
- Library mode (in-process encryption)
- Sensitive field registry
- Legacy format migration
- Nonce collision analysis
- Key compromise response procedure (10-step process)
- Key access control at provider level
- Ciphertext envelope format (`vault:v1:...`)

These controls now belong to the **upstream encryption service**, not vsql-vault.
