# VibeSQL Vault

**Governed storage for encrypted data. Drop it next to Micro. Shrink your PCI scope.**

VibeSQL Vault is a hardened storage service for encrypted data. It doesn't encrypt. It doesn't decrypt. It stores opaque blobs that were encrypted somewhere else — Azure Key Vault, your own crypto stack, doesn't matter — and governs access to them.

Think safety deposit box, not locksmith.

Paired with [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro), it becomes the smallest possible PCI cardholder data environment: one 77MB database binary, one ~10MB vault API. Two processes, governed storage, complete audit trail. That's your entire CDE.

---

## The Micro + Vault CDE

```
Traditional PCI CDE:
  App servers + load balancers + database cluster + key management
  + encryption middleware + audit logging + network segmentation
  = months of scoping, dozens of components in scope

VibeSQL CDE:
  ┌─────────────────────────────────────┐
  │  vsql-vault pod                      │
  │                                      │
  │  ┌───────────────┐                  │
  │  │ vsql-vault    │  Rust binary,    │
  │  │ API           │  FROM scratch,   │
  │  │ (port 8443)   │  ~10MB           │
  │  └───────┬───────┘                  │
  │          │                           │
  │  ┌───────┴───────┐                  │
  │  │ VibeSQL Micro │  77MB binary,    │
  │  │ (port 5432)   │  pod-internal    │
  │  └───────────────┘                  │
  └─────────────────────────────────────┘
  = two binaries, one pod, minimal attack surface
```

Micro's port is **not exposed** outside the pod. Only the vault API talks to it.

**Why this matters for compliance:** PCI DSS scopes every system that stores, processes, or transmits cardholder data. Fewer systems in scope = less audit surface = faster certification. Micro + Vault is the minimum viable CDE.

---

## How It Works

```
Store:
  Your Encryption Stack              vsql-vault
  (Azure KV, PayEz Encryption,      (governed storage)
   any crypto you trust)

    plaintext → encrypt → blob  ──►  PUT /vault/{purpose}/{id}
                                      + metadata, ownership,
                                      retention policy, access
                                      contract

Retrieve:
                                      GET /vault/{purpose}/{id}  ──►  blob → decrypt → plaintext
                                      (only if caller is             (your crypto stack
                                       authorized per contract)       handles decryption)
```

vsql-vault never sees plaintext. It never parses the blob. It doesn't care what algorithm was used. The blob is opaque bytes with metadata.

### What vsql-vault governs

- **Access policies.** Who stored this? Who can retrieve it? Under what contract?
- **Retention policies.** When does it expire? What's the max retention? Auto-purge scheduling.
- **Audit trail.** Every store, retrieve, and purge is logged with caller identity, timestamp, and grant/deny.
- **Purge proof.** SHA-256 hash of the entry at time of deletion. Cryptographic proof it existed and was destroyed.
- **Compliance evidence.** Point-in-time snapshots for your QSA: entries by purpose, key staleness, purge compliance, access summary.

---

## Quick Start (with VibeSQL Micro)

### 1. Start Micro

```bash
./vibesql-micro
# Micro is running on :5432
```

### 2. Configure Vault

```toml
# vsql-vault.toml

[server]
listen_addr = "0.0.0.0:8443"

[storage]
database_url = "postgresql://vsql_vault@localhost:5432/vault"

[auth]
api_key_header = "X-Vault-Key"
api_key_env = "VSQL_VAULT_API_KEY"

[purge]
sweep_interval_hours = 24
purge_proof_hash = true
```

### 3. Start Vault

```bash
VSQL_VAULT_API_KEY=your-secret-key ./vsql-vault --config vsql-vault.toml
# Vault API is running on :8443
```

### 4. Set a Retention Policy

```bash
curl -X PUT http://localhost:8443/admin/retention-policies/card \
  -H "X-Vault-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "max_retention_days": 365,
    "default_ttl_days": 90,
    "purge_method": "physical-delete",
    "require_purge_proof": true,
    "description": "Card tokens — max 1 year, default 90 days"
  }'
```

### 5. Store an Encrypted Blob

```bash
# Your encryption stack encrypts the data first.
# Then store the opaque ciphertext in the vault.
curl -X PUT http://localhost:8443/vault/card/payment-12345 \
  -H "X-Vault-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "encrypted_value": "vault:v1:AES256-GCM:keyid=7:base64ciphertext...",
    "algorithm_hint": "AES-256-GCM",
    "key_ref": "akv:payez-kv:card-key-v7",
    "metadata": { "merchant_id": 42 },
    "expires_at": "2027-02-16T00:00:00Z",
    "access_policy": "payment-service-only"
  }'
```

### 6. Retrieve It

```bash
curl http://localhost:8443/vault/card/payment-12345 \
  -H "X-Vault-Key: your-secret-key"

# Returns the opaque blob + metadata. Your app decrypts it.
```

---

## API

| Method | Path | Purpose |
|--------|------|---------|
| `PUT` | `/vault/{purpose}/{external_id}` | Store an encrypted blob |
| `GET` | `/vault/{purpose}/{external_id}` | Retrieve (if authorized) |
| `DELETE` | `/vault/{purpose}/{external_id}` | Manually purge an entry |
| `HEAD` | `/vault/{purpose}/{external_id}` | Check existence + expiry (no blob) |
| `GET` | `/vault/{purpose}` | List entries for a purpose (metadata only) |
| `PUT` | `/admin/retention-policies/{purpose}` | Create/update retention policy |
| `PUT` | `/admin/access-policies/{name}` | Create/update access policy |
| `GET` | `/admin/access-log` | Query access log |
| `GET` | `/admin/purge-log` | Query purge log |
| `POST` | `/admin/purge/sweep` | Trigger manual purge sweep |
| `GET` | `/compliance/report` | PCI Req 3 compliance evidence snapshot |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

---

## Access Policies

Who can store and retrieve entries.

| Policy | Store | Retrieve | Description |
|--------|-------|----------|-------------|
| `owner-only` | Any authenticated | Only the `owner_app` that stored it | Default — only the storer can retrieve |
| `same-purpose` | Any authenticated | Any app with the same purpose | Shared access within a purpose |
| `open-retrieve` | Any authenticated | Any authenticated caller | Store controlled, retrieve open |
| `admin-only` | Admin apps | Admin apps | Locked down for regulatory data |

Custom policies define rules per operation with `allowed_apps`, `require_identity`, and `max_retrievals`.

---

## Retention Policies

How long data can be stored. What happens when it expires.

| Enforcement | What Happens |
|-------------|-------------|
| Store request exceeds `max_retention_days` | Rejected with 422 |
| No `expires_at` provided | Set to `NOW() + default_ttl_days` |
| Entry expires | Purge sweep deletes it per `purge_method` |
| Retrieve expired entry | Returns 410 Gone |

### Purge Methods

| Method | Action | Proof |
|--------|--------|-------|
| `physical-delete` | Row deleted. SHA-256 proof written to `purge_log`. | Hash of entry at time of purge |
| `crypto-shred` | Value zeroed in place. Row kept with `purged_at` set. | Zeroed value + purge log entry |
| `retention-expire` | Same as physical-delete, reason marked as retention policy. | Purge log with policy reference |

---

## PCI DSS v4.0 Requirement 3 Coverage

| PCI Req | Requirement | Vault Control |
|---------|-------------|---------------|
| **3.1.1** | Data retention policies | Retention policies per purpose with max_retention_days and enforced TTL |
| **3.1.2** | Data limited to what is needed | Purpose-scoped storage with expiry. Purge sweep enforces removal. |
| **3.3.2** | PAN rendered unreadable | Vault stores already-encrypted values. Never sees plaintext. |
| **3.5.1** | Access to crypto keys restricted | Vault doesn't hold keys. Keys are in Azure KV / HC Vault / AWS KMS. |
| **3.6.1.4** | Key changes at cryptoperiod end | Tracks `key_ref` per entry. Reports entries on stale keys. |
| **3.7.1** | Key management policies documented | `/compliance/report` generates policy, key states, purge compliance. |

---

## Compliance Report

`GET /compliance/report` generates a point-in-time snapshot:

```json
{
  "summary": {
    "total_entries": 12847,
    "active_entries": 11203,
    "expired_pending_purge": 44,
    "purged_last_30_days": 1600
  },
  "by_purpose": {
    "card": {
      "active": 8200,
      "retention_policy": "365 days max, 90 day default TTL",
      "entries_expiring_next_30_days": 320,
      "key_refs": {
        "akv:payez-kv:card-key-v7": 7800,
        "akv:payez-kv:card-key-v6": 400
      }
    }
  },
  "purge_compliance": {
    "purge_sweep_last_run": "2026-02-16T04:00:00Z",
    "entries_purged_last_sweep": 12,
    "purge_proof_available": true
  }
}
```

Hand this to your QSA. Requirement 3 evidence, generated automatically.

---

## Security Posture

| Layer | Control |
|-------|---------|
| Container | FROM scratch — no shell, no package manager, no utilities |
| Network | Pod-internal PostgreSQL. Only vault API port exposed. TLS required. |
| Storage | VibeSQL Micro on dedicated disk. Not shared with application data. |
| Auth | mTLS, JWT with JWKS validation, or API key. No anonymous access. |
| Authorization | Per-entry access policies. Every operation logged. |
| Memory | Rust — no GC, `zeroize` for sensitive buffers, `mlock` to prevent swap |
| Audit | Every operation logged to `vault.access_log`. Immutable. |

---

## Performance

| Operation | Target |
|-----------|--------|
| Store (PUT) | < 5ms |
| Retrieve (GET) | < 3ms |
| HEAD (exists check) | < 2ms |
| Purge sweep (1000 entries) | < 10s |
| Compliance report | < 5s |

---

## Storage Tables

```
vault.entries            — Encrypted blobs with metadata, TTL, access policy
vault.access_log         — Every store/retrieve/purge logged with caller + grant/deny
vault.access_policies    — Named access contracts (who can store/retrieve/purge)
vault.retention_policies — Per-purpose TTL, max retention, purge method
vault.purge_log          — Proof of deletion (SHA-256 hash, method, reason)
```

---

## The VibeSQL Compliance Stack

```
┌────────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────┐
│ VibeSQL    │  │ VibeSQL    │  │ VibeSQL  │  │ VibeSQL      │
│ Micro      │  │ Vault      │  │ Audit    │  │ Edge         │
│ (database) │  │ (Req 3)    │  │ (Req 10) │  │ (auth)       │
│ 77MB       │  │ ~10MB      │  │          │  │              │
└────────────┘  └────────────┘  └──────────┘  └──────────────┘
     │               │               │              │
     └───── Micro + Vault = minimal CDE ────────────┘
```

- [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro) — Single-binary PostgreSQL. Dev tool and CDE companion.
- [VibeSQL Server](https://github.com/PayEz-Net/vibesql-server) — Production multi-tenant PostgreSQL server
- [VibeSQL Edge](https://github.com/PayEz-Net/vibesql-edge) — Authentication gateway
- [VibeSQL Audit](https://github.com/PayEz-Net/vibesql-audit) — PCI DSS compliant audit logging (Req 10)
- [Vibe SDK](https://github.com/PayEz-Net/vibe-sdk) — TypeScript ORM with live schema sync

---

## License

Apache 2.0 License. See [LICENSE](LICENSE).

---

<div align="right">
  <sub>Part of <a href="https://vibesql.online">VibeSQL</a> · Powered by <a href="https://idealvibe.online">IdealVibe</a></sub>
</div>
