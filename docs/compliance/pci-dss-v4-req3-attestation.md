# VibeSQL Vault -- PCI DSS v4.0 Requirement 3 Attestation

**Component**: VibeSQL Vault (`vsql-vault`) — Governed Opaque Storage Vault
**Version**: 0.1.0
**Audit baseline**: `bc167038a70da3c58e4282f2966213271ffe1d72`
**Remediation commit**: `d8073965be3cc450bbceaac044c91cd1fb30ca90`
**Date**: 2026-02-16
**Assessor**: QSAPert (PCI DSS SAQ-D Security Review)
**Standard**: PCI DSS v4.0 (March 2022, mandatory March 2025)

---

## Attestation Status

**4 of 6 findings verified fixed in code.** 2 findings have approved remediation designs pending implementation and final verification.

This attestation will be unconditional (0 open findings) when:
1. Finding 5 (TLS) is implemented and verified
2. Finding 6 (mandatory retention) is implemented and verified

---

## Scope Statement

vsql-vault is a **governed opaque storage vault**. It stores pre-encrypted blobs with access control, retention enforcement, audit logging, and purge proof. It does NOT encrypt, decrypt, or manage cryptographic keys.

vsql-vault's PCI DSS v4.0 Requirement 3 scope is limited to:
- **Req 3.1** — Data retention policies, access governance, audit trails
- **Req 3.3.2** (partial) — Stored data is opaque ciphertext

The following are **out of scope** (upstream crypto provider responsibility):
- Req 3.5 — Encryption strength
- Req 3.6 — Key management
- Req 3.7 — Key management policies

Full control mapping: see `pci-dss-v4-req3-audit-brief.md` in this directory.

---

## Finding Disposition

### Finding 1: Audit Logging Is Fire-and-Forget

| Field | Value |
|-------|-------|
| PCI Requirement | 3.1.1, 10.2 |
| Severity | High |
| Status | **VERIFIED FIXED** |
| Commit | `d807396` |

**Original issue**: `log_and_forget()` allowed vault operations to succeed without an audit record.

**Remediation verified**: `log_and_forget()` replaced with `audit_log()` returning `Result<(), Response>`. On audit write failure, all handlers return HTTP 503 (`"audit subsystem unavailable — operation blocked for compliance"`). No vault operation can succeed without a corresponding audit record.

**Evidence**: `api.rs:557-582` — `audit_log()` function. All 5 handlers (store, retrieve, delete, head, list) check the result and abort on failure.

---

### Finding 2: Caller Identity Not Extracted from Auth Context

| Field | Value |
|-------|-------|
| PCI Requirement | 3.1.2, 10.2.1 |
| Severity | High |
| Status | **VERIFIED FIXED** |
| Commit | `d807396` |

**Original issue**: `caller_app` hardcoded to `"authenticated-caller"` for retrieve, delete, head, and list operations.

**Remediation verified**: `auth_middleware` extracts caller identity from `X-Vault-Caller` header, injects `AuthContext` into request extensions. All handlers extract `auth.caller_id` via `Extension<AuthContext>`. Default fallback is `"api-key-holder"` (identifiable, not anonymous).

**Evidence**: `middleware.rs:35-46` — `AuthContext` injection. `api.rs` — all handlers use `Extension(auth): Extension<AuthContext>`. Integration test `test_caller_identity_from_header`.

**Residual note** (Low, not a finding): In API-key auth mode, the `X-Vault-Caller` header is caller-asserted. Production deployments using JWT or mTLS should derive caller identity from token claims or certificate subject, not a header. This is a limitation of the API-key auth mode, not a regression.

---

### Finding 3: Access Policy Not Retrieved from Entry on Retrieve

| Field | Value |
|-------|-------|
| PCI Requirement | 3.1.2 |
| Severity | High |
| Status | **VERIFIED FIXED** |
| Commit | `d807396` |

**Original issue**: Retrieve handler hardcoded `policy_name = "owner-only"`, ignoring the `access_policy` stored on the entry.

**Remediation verified**: `access_policy: String` field added to `VaultEntry` with `#[serde(default = "default_access_policy")]`. Persisted in SQL on store (`INSERT ... access_policy`), read back on retrieve (`SELECT ... access_policy`), and evaluated against the stored policy name. Custom access contracts are now enforced as stored.

**Evidence**: `entry.rs:17-21` — field definition. `pg_storage.rs` — SQL includes `access_policy` in INSERT, UPDATE, and SELECT. `api.rs:272` — `let policy_name = &entry.access_policy`. Integration test `test_stored_access_policy_returned` — stores with `"same-purpose"`, retrieves, verifies roundtrip.

---

### Finding 4: Purge Sweep Does Not Generate Purge Proof

| Field | Value |
|-------|-------|
| PCI Requirement | 3.1.1 |
| Severity | Medium |
| Status | **VERIFIED FIXED** |
| Commit | `d807396` |

**Original issue**: `purge_expired()` performed bulk `DELETE` without recording purge proof entries.

**Remediation verified**: PgStorage uses `DELETE ... RETURNING` inside a transaction. For each deleted entry: computes SHA-256 proof hash via `compute_proof_hash()`, writes to `purge_log` with `purge_method = "retention-expire"`, `purge_reason = "ttl-expired"`, `purged_by = "system/purge-scheduler"`. Transaction commits atomically — either all proofs are recorded and entries deleted, or nothing changes.

MemoryStorage: equivalent logic — collects expired entries, computes proof hashes, records to purge_log, then removes entries.

**Evidence**: `pg_storage.rs:133-187` — transactional purge with RETURNING. `memory.rs:111-142` — equivalent in-memory implementation. Integration test `test_purge_expired_generates_proof` — verifies `sha256:` hash, `"ttl-expired"` reason, and `"retention-expire"` method.

---

### Finding 5: No TLS in Current Build

| Field | Value |
|-------|-------|
| PCI Requirement | Req 4.2.1 |
| Severity | Medium |
| Status | **REMEDIATION APPROVED — pending implementation** |
| Decision | BAPert, 2026-02-16 |

**Original issue**: Vault API runs plain HTTP. Metadata (purpose, owner_app, tags) transits unencrypted.

**Approved remediation design**:
- Built-in TLS via `rustls` (no OpenSSL dependency, compatible with FROM scratch image)
- Two startup modes controlled by configuration:
  - `mode = "dev"` — HTTP allowed. Loud startup warning: `"dev mode, not for production use"`. For local development and testing only.
  - `mode = "prod"` — TLS required. Must configure `cert_path` and `key_path`. **Refuses to start** without valid TLS configuration. Hard error, not a warning.
- No self-signed certificate generation. No reverse proxy assumption. Operators must provide their own certificates.

**Verification criteria** (for re-review after implementation):
- [ ] `mode = "prod"` without `cert_path` + `key_path` → startup failure (hard error)
- [ ] `mode = "dev"` logs a visible warning on every startup
- [ ] `mode = "prod"` with valid certs → TLS listener on configured port
- [ ] Integration test verifying prod mode startup rejection without certs
- [ ] No OpenSSL dependency (`cargo tree | grep openssl` returns nothing)

---

### Finding 6: Retention Policy Not Enforced When No Policy Exists

| Field | Value |
|-------|-------|
| PCI Requirement | 3.1.1 |
| Severity | Low |
| Status | **REMEDIATION APPROVED — pending implementation** |
| Decision | BAPert, 2026-02-16 |

**Original issue**: Entries could be stored under any purpose without a retention policy, persisting indefinitely.

**Approved remediation design**:
- **Mandatory retention**: reject stores to any purpose that does not have a retention policy configured
- Store handler checks for retention policy. If none exists for the requested purpose → HTTP 422 with clear error message
- Admin must create a retention policy for a purpose before any entries can be stored under it
- This is the strictest option and the correct default for an open source compliance product: **secure by default, governed by default**

**Verification criteria** (for re-review after implementation):
- [ ] `PUT /v1/vault/{purpose}/{id}` without a retention policy for `{purpose}` → HTTP 422
- [ ] Error message clearly states a retention policy must be created first
- [ ] Integration test verifying rejection
- [ ] Existing tests still pass (test fixtures create retention policies where needed)

---

## Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Fire-and-forget audit logging | High | **Verified fixed** (`d807396`) |
| 2 | Hardcoded caller identity | High | **Verified fixed** (`d807396`) |
| 3 | Hardcoded access policy on retrieve | High | **Verified fixed** (`d807396`) |
| 4 | Purge sweep skips proof | Medium | **Verified fixed** (`d807396`) |
| 5 | No TLS in current build | Medium | **Remediation approved** — pending build + verify |
| 6 | No mandatory retention policy | Low | **Remediation approved** — pending build + verify |

**Test status at `d807396`**: 59 tests passing (56 original + 3 new), 0 clippy warnings, fmt clean.

**Next steps**:
1. Implement Finding 5 (TLS with dev/prod modes) and Finding 6 (mandatory retention)
2. QSAPert re-verifies against the implementation commit
3. This document is updated to **unconditional attestation** with 0 open findings
4. Final commit hash stamped as the attested version

---

## Signatures

| Role | Name | Date |
|------|------|------|
| Security Assessor | QSAPert | 2026-02-16 |
| Architecture / Product | BAPert | 2026-02-16 |
| Engineering | [Pending — signs after findings 5+6 implemented] | |

---

*This attestation covers PCI DSS v4.0 Requirement 3 (Protect Stored Account Data) as it applies to vsql-vault's governed opaque storage controls. Encryption controls (Req 3.5, 3.6, 3.7) are out of scope — assess at the upstream crypto provider.*
