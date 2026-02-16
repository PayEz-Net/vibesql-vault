# VibeSQL Vault

**Field-level encryption for VibeSQL. Drop it next to Micro. Shrink your PCI scope.**

VibeSQL Vault encrypts sensitive fields inside JSONB documents — card numbers, PII, secrets — before they reach PostgreSQL. Paired with [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro), it becomes the smallest possible PCI cardholder data environment: one 77MB database binary, one ~10MB encryption proxy. Two processes, complete field-level protection, governed key lifecycle. That's your entire CDE.

No TDE. No full-disk encryption where every authenticated query sees cleartext. Vault encrypts individual fields inside your JSONB documents. Non-sensitive data stays queryable. Sensitive data is opaque ciphertext that only Vault can decrypt.

---

## The Micro + Vault CDE

```
Traditional PCI CDE:
  App servers + load balancers + database cluster + key management
  + encryption middleware + audit logging + network segmentation
  = months of scoping, dozens of components in scope

VibeSQL CDE:
  ┌──────────────────┐     ┌──────────────────┐
  │ VibeSQL Micro    │     │ VibeSQL Vault    │
  │ (database, 77MB) │◄────│ (encryption,~10MB)│
  │ :5432            │     │ :5433            │
  └──────────────────┘     └──────────────────┘
  = two binaries, one machine, minimal attack surface
```

Your application connects to Vault on port 5433 instead of Micro on 5432. That's the only change. Vault intercepts the PostgreSQL wire protocol, encrypts sensitive JSONB fields on write, decrypts on read, and forwards everything else untouched.

**Why this matters for compliance:** PCI DSS scopes every system that stores, processes, or transmits cardholder data. Fewer systems in scope = less audit surface = faster certification. Micro + Vault is the minimum viable CDE.

---

## How It Works

```
Your Application (any language)
  │
  │  PostgreSQL wire protocol (port 5433)
  ▼
┌──────────────────────────────────────────┐
│ VibeSQL Vault (Rust binary, port 5433)    │
│                                           │
│  Write path:                              │
│    Parse query → match sensitive_fields   │
│    → encrypt tagged JSONB fields          │
│    → forward to VibeSQL (Micro or Server) │
│                                           │
│  Read path:                               │
│    Receive result from VibeSQL            │
│    → detect vault:v1:... envelopes        │
│    → decrypt with current or grace key    │
│    → return cleartext to application      │
└──────────────────┬───────────────────────┘
                   │  upstream, port 5432
                   ▼
            ┌──────────────┐
            │ VibeSQL      │
            │ Micro/Server │
            └──────────────┘
```

### What Gets Encrypted

Individual fields inside JSONB documents:

```json
// Before Vault:
{
  "merchant": "Acme Corp",
  "amount": 49.99,
  "card_number": "4111111111111111",
  "cardholder_name": "Jane Doe"
}

// After Vault:
{
  "merchant": "Acme Corp",
  "amount": 49.99,
  "card_number": "vault:v1:AES256-GCM:keyid=7:base64ciphertext...",
  "cardholder_name": "vault:v1:AES256-GCM:keyid=7:base64ciphertext..."
}
```

`merchant` and `amount` stay queryable. `card_number` and `cardholder_name` are opaque ciphertext. Only Vault can decrypt them.

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

[proxy]
listen_addr = "127.0.0.1:5433"
upstream_addr = "127.0.0.1:5432"    # VibeSQL Micro

[key_provider]
provider = "local-dev"               # Development only

[key_provider.local_dev]
passphrase_file = "./dev-keys.txt"   # NEVER use in production

[registry]
database_url = "postgresql://postgres:postgres@localhost:5432/vibesql"
refresh_interval_secs = 60

[key_lifecycle]
rotation_days = 90
grace_period_days = 275
total_lifetime_days = 365
auto_reencrypt_on_access = true
```

### 3. Start Vault

```bash
./vsql-vault --config vsql-vault.toml
# Vault is running on :5433, proxying to Micro on :5432
```

### 4. Register Sensitive Fields

```sql
-- Connect to Micro directly for admin operations
INSERT INTO vibe_audit.sensitive_fields
    (schema_name, table_name, json_path, redact_in_log, encrypt_at_rest, key_purpose, description)
VALUES
    ('collections', 'payments', '$.card_number',     TRUE, TRUE, 'card',    'PAN — PCI DSS Req 3.3.2'),
    ('collections', 'payments', '$.cardholder_name', TRUE, TRUE, 'general', 'Cardholder name — PII'),
    ('collections', 'payments', '$.card_expiry',     TRUE, TRUE, 'card',    'Expiration date');
```

### 5. Connect Your App to Vault

```bash
# Point your app at Vault (:5433) instead of Micro (:5432)
# Everything else is transparent
psql -h localhost -p 5433 -d vibesql
```

Queries go through Vault. Sensitive fields are encrypted on write, decrypted on read. Your application sees cleartext. PostgreSQL stores ciphertext.

---

## Ciphertext Envelope

```
vault:v1:AES256-GCM:keyid={id}:{base64(nonce || ciphertext || tag)}
```

| Field | Purpose |
|-------|---------|
| `vault` | Prefix — identifies a Vault-encrypted value |
| `v1` | Envelope version — future-proof for format changes |
| `AES256-GCM` | Algorithm (AES-256-GCM, the only supported algorithm) |
| `keyid={id}` | Key identifier — resolves to a specific version in the key provider |
| `base64(...)` | 12-byte nonce + ciphertext + 16-byte GCM authentication tag |

Self-describing. Decryption needs only the key provider — no external metadata.

---

## Key Management

Vault doesn't store keys. It delegates to a provider.

### Providers

| Provider | Use Case |
|----------|----------|
| `azure-keyvault` | Production with Azure. RSA 4096 wrapping, AES-256 symmetric. Managed identity or service principal. |
| `hashicorp-vault` | Production with HashiCorp. Transit secrets engine. |
| `aws-kms` | Production with AWS. KMS envelope encryption. |
| `local-dev` | **Development only.** Keys from a local passphrase file. Logged on startup. |

### Key Lifecycle

```
┌──────────┐    rotate     ┌──────────┐   grace expires  ┌──────────┐
│ Current  │──────────────►│ Grace    │─────────────────►│ Retired  │
│          │               │          │                   │          │
│ encrypt  │               │ decrypt  │                   │ cannot   │
│ + decrypt│               │ only     │                   │ decrypt  │
└──────────┘               └──────────┘                   └──────────┘
```

Keys rotate automatically. During the grace period, Vault decrypts with the old key and re-encrypts with the current key on read. Documents naturally migrate to the current key through normal traffic. No downtime, no big-bang re-encryption.

---

## Sensitive Field Registry

Vault shares the `vibe_audit.sensitive_fields` table with [VibeSQL Audit](https://github.com/PayEz-Net/vibesql-audit). Register a field once — it's encrypted at rest (Req 3), access-logged with redaction (Req 10), and key-governed with evidence.

| Column | Consumer | What It Does |
|--------|----------|-------------|
| `json_path` | Vault + Audit | Identifies the JSONB field |
| `encrypt_at_rest = TRUE` | Vault | Encrypts this field before storage |
| `redact_in_log = TRUE` | Audit | Masks this field in audit events |
| `key_purpose` | Vault | Selects which key set to use |
| `auto_reencrypt = TRUE` | Vault | Re-encrypt on grace-key access |

One INSERT, two compliance requirements.

---

## VibeSQL Audit Integration

When deployed with [VibeSQL Audit](https://github.com/PayEz-Net/vibesql-audit), Vault creates a closed compliance loop:

```
vibe_audit.sensitive_fields (single registry)

  ┌──────────────┐     ┌──────────────┐
  │ VibeSQL      │     │ VibeSQL      │
  │ Audit        │     │ Vault        │
  │ (Req 10)     │     │ (Req 3)      │
  │              │     │              │
  │ "access was  │     │ "data is     │
  │  logged and  │     │  encrypted   │
  │  field was   │     │  at rest     │
  │  redacted"   │     │  with key Y" │
  └──────────────┘     └──────────────┘
```

- **WAL capture sees ciphertext.** Audit's WAL logical decoding never sees cardholder data — it's already encrypted. Defense in depth.
- **Re-encryption events emit to Audit.** When Vault rotates a key and re-encrypts a field, the event is logged.
- **Shared registry.** One registration covers both encryption and audit.

---

## Admin API

Local HTTP API on port 9100. Localhost only. Requires API key.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Key provider reachable, keys available, registry loaded |
| `GET` | `/health/ready` | Readiness probe (also checks upstream VibeSQL) |
| `GET` | `/metrics` | Prometheus metrics — encrypt/decrypt counts, latency, cache hit rates |
| `GET` | `/v1/keys` | Active key sets per purpose (IDs only, no material) |
| `POST` | `/v1/keys/rotate` | Trigger immediate key rotation |
| `GET` | `/v1/fields` | List registered sensitive fields |
| `POST` | `/v1/fields` | Register a new sensitive field |
| `POST` | `/v1/reencrypt` | Trigger bulk re-encryption sweep |
| `GET` | `/v1/compliance/report` | PCI Req 3 compliance evidence snapshot |

---

## PCI DSS v4.0 Requirement 3 Coverage

| PCI Req | Requirement | Vault Control |
|---------|-------------|---------------|
| **3.3.2** | PAN rendered unreadable anywhere stored | AES-256-GCM via vault envelope. PAN is opaque ciphertext in PostgreSQL. |
| **3.5.1** | Cryptographic key access restricted | Key material in provider (Azure KV / HashiCorp / AWS KMS). Vault retrieves on demand, caches with TTL. No keys on disk. |
| **3.5.1.1** | Key access restricted to fewest custodians | Provider RBAC. Vault service identity has encrypt/decrypt only — no export. |
| **3.6.1** | Key management procedures implemented | Lifecycle config: rotation, grace period, retirement — all automated. |
| **3.6.1.1** | Strong cryptographic key generation | Provider's certified RNG (FIPS 140-2 Level 2/3 for Azure HSM). |
| **3.6.1.2** | Secure key distribution | Keys never leave the provider. TLS in transit. `zeroize` + `mlock` in memory. |
| **3.6.1.4** | Key changes at end of cryptoperiod | Automatic rotation per config. Auto re-encrypt on read migrates data. Bulk re-encrypt API for immediate sweep. |
| **3.7.1** | Key management policies documented | `/v1/compliance/report` generates full policy, key states, rotation history. |

---

## Searchable Encryption (Blind Indexes)

Encrypted fields can't be queried directly. For lookup-by-value, Vault supports blind indexes — HMAC-based hashes stored alongside the ciphertext.

```sql
-- Application sends:
SELECT * FROM collections.payments WHERE data->>'card_number' = '4111111111111111';

-- Vault rewrites to:
SELECT * FROM collections.payments WHERE data->>'card_number__idx' = 'bidx:v1:HMAC-SHA256:computed_hash';
```

Equality only. No range queries, no LIKE. Optional per-field.

---

## Performance

| Operation | Target |
|-----------|--------|
| Passthrough (no sensitive fields) | < 100μs |
| Encrypt one JSONB field | < 50μs |
| Decrypt one JSONB field | < 50μs |
| Transform 5-field document | < 300μs |
| Key provider retrieval (cache miss) | < 200ms (network bound) |

Written in Rust. Key material uses `zeroize` — zeroed on drop, no lingering cleartext. `mlock` prevents swap to disk. No garbage collector.

---

## Configuration Reference

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `VSQL_VAULT_AZURE_CLIENT_SECRET` | Azure service principal secret |
| `VSQL_VAULT_HC_TOKEN` | HashiCorp Vault token |
| `VSQL_VAULT_HC_SECRET_ID` | HashiCorp AppRole secret ID |
| `VSQL_VAULT_ADMIN_KEY` | Admin API authentication key |
| `VSQL_VAULT_DB_PASSWORD` | Registry database password |

Secrets are never in the config file.

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
