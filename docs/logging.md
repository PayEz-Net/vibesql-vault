# Logging

vsql-vault emits structured JSON log lines to **stdout** via the `tracing` crate. Each line is a JSON object — e.g.:

```json
{"timestamp":"2026-04-20T13:46:31.068229Z","level":"INFO","fields":{"message":"migrations applied"},"target":"vsql_vault_server"}
```

There is **no log-shipping library** built into vsql-vault. Operators choose their preferred sink via the container runtime's log-driver plugin mechanism (Docker's `--log-driver`, Kubernetes log agents, systemd journal forwarders, etc.). This keeps the binary small, minimises dependencies, and lets the same image ship logs to any popular backend.

## Pluggable transports

### Graylog (GELF)

```bash
docker run -d --name vsql-vault \
  --log-driver gelf \
  --log-opt gelf-address=udp://graylog-host:12201 \
  --log-opt tag=vsql-vault \
  --log-opt labels=service,env \
  --label service=vsql-vault \
  --label env=prod \
  ...
  vsql-vault:latest
```

Each GELF message exposes `container_name`, `image_name`, `tag`, `service`, and `env` as indexable fields. The vsql-vault JSON line lands in the `message` field; configure a Graylog extractor (JSON) on that field if you want `level`, `target`, etc. promoted to top-level fields.

### Fluentd / Fluent Bit (→ Loki, Elastic, S3, anywhere Fluent can route)

```bash
docker run -d --name vsql-vault \
  --log-driver fluentd \
  --log-opt fluentd-address=fluentd-host:24224 \
  --log-opt tag=vsql.vault \
  ...
  vsql-vault:latest
```

### AWS CloudWatch

```bash
docker run -d --name vsql-vault \
  --log-driver awslogs \
  --log-opt awslogs-region=us-east-1 \
  --log-opt awslogs-group=vsql-vault \
  ...
  vsql-vault:latest
```

### Host syslog / journald

```bash
docker run -d --name vsql-vault --log-driver journald ...   # systemd-journald
docker run -d --name vsql-vault --log-driver syslog   ...   # local syslog
```

### None (quiet)

```bash
docker run -d --name vsql-vault --log-driver none ...
```

## Kubernetes

In Kubernetes, the container runtime captures stdout and the cluster's log agent (Fluent Bit, Vector, Datadog agent, Splunk Universal Forwarder, etc.) forwards to your chosen backend. No vsql-vault configuration required — just ensure the cluster log agent is installed and configured.

## Why structured JSON to stdout

- **No backend lock-in.** Swap Graylog→Loki→CloudWatch without touching the binary.
- **Smaller image.** No shipping SDKs bundled. Rust binary stays ~10MB.
- **Audit trail is separate.** Compliance-grade entries already live in `vsql_vault.access_log` inside the vault DB — not dependent on the logging pipeline. Ops logs (stdout) are for debugging; audit logs (DB table) are for auditors.

## Recommended fields to extract

If you're configuring Graylog/Elastic/Loki pipelines, these are the high-value fields from the vsql-vault JSON payload:

| Field | Example | Use |
|---|---|---|
| `level` | `INFO`, `WARN`, `ERROR` | severity filtering |
| `target` | `vsql_vault_server` | module routing |
| `fields.message` | `"migrations applied"` | human-readable event |
| `timestamp` | ISO 8601 UTC | time ordering |

Request-scoped logs (when a caller hits the API) include `caller_app`, `purpose`, `entry_id`, and `operation` in `fields`. For access-control decisions, the DB `access_log` is the source of truth — the stdout log is a convenience trail.
