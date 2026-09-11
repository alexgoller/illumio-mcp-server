---
title: Audit log
layout: default
parent: Operations
---

# Audit Log

The audit log is the authoritative record of "who called what tool and whether it was allowed." It is written by the dispatcher for every tool-call decision in HTTP auth mode.

---

## Schema

The audit log lives in a SQLite database (default path alongside the keystore). Every record corresponds to one dispatcher decision.

```sql
CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,       -- ISO-8601 UTC timestamp
    sub          TEXT,                -- IdP subject (user identity, NULL in stdio)
    iss          TEXT,                -- IdP issuer URL (NULL in stdio)
    tool         TEXT NOT NULL,       -- MCP tool name, e.g. "provision-policy"
    decision     TEXT NOT NULL,       -- "allowed" | "denied" | "error"
    reason       TEXT,                -- short machine-readable reason code (see below)
    role         TEXT,                -- "reader" | "operator" | "admin" | NULL
    request_id   TEXT                 -- UUID from X-Request-Id header
);

-- Indexes for common query patterns
CREATE INDEX idx_audit_log_sub_ts    ON audit_log(sub, ts DESC);
CREATE INDEX idx_audit_log_decision  ON audit_log(decision, ts DESC);
```

### Column meanings

| Column | Notes |
|---|---|
| `ts` | UTC timestamp in ISO-8601 format. Monotonically increasing within a process. |
| `sub` | The IdP `sub` claim — stable per user, not a display name. Map to display names via your IdP's directory. |
| `iss` | The IdP issuer URL. Present for multi-IdP deployments (reserved for future use). |
| `tool` | The MCP tool name as registered in `TOOL_REGISTRY`. |
| `decision` | `allowed` — call was dispatched to the handler. `denied` — authz check failed. `error` — handler raised an exception. |
| `reason` | Machine-readable code for denials. Values include: `forbidden_no_role`, `forbidden`, `no_pce_credentials`, `confirm_required`, `confirm_token_replay`, `invalid_confirm_token`. |
| `role` | The role the user was granted at the time of the call. `NULL` if no role was assigned (for `forbidden_no_role` decisions). |
| `request_id` | Matches the `X-Request-Id` response header on the corresponding HTTP request. Use this to correlate audit entries with HTTP server logs. |

---

## File location

The audit database path is controlled by `MCP_AUDIT_LOG_PATH`. If not set, it defaults to `<keystore_directory>/audit.db`, where the keystore directory is derived from `MCP_KEYSTORE_PATH` (default `./data`). So by default the audit database is at `./data/audit.db`.

The file is created at server startup with `chmod 600` permissions.

In stdio mode, no audit log is written — a `NullAuditLog` is used.

---

## Sample queries

```sql
-- Recent denied calls per user (last 24h)
SELECT ts, sub, tool, reason
FROM audit_log
WHERE decision = 'denied'
  AND ts > datetime('now', '-1 day')
ORDER BY ts DESC
LIMIT 50;

-- Tool-call volume by user (last 7 days)
SELECT sub, COUNT(*) AS calls
FROM audit_log
WHERE ts > datetime('now', '-7 days')
GROUP BY sub
ORDER BY calls DESC;

-- Who provisioned policy and when
SELECT ts, sub, role, request_id
FROM audit_log
WHERE tool = 'provision-policy'
  AND decision = 'allowed'
ORDER BY ts DESC;

-- Calls by a specific user
SELECT ts, tool, decision, reason
FROM audit_log
WHERE sub = 'user-object-id-from-idp'
ORDER BY ts DESC
LIMIT 100;

-- Error rate by tool
SELECT tool, COUNT(*) AS errors
FROM audit_log
WHERE decision = 'error'
GROUP BY tool
ORDER BY errors DESC;
```

---

## What is NOT logged

The audit log deliberately excludes:

- **Tool arguments** — PCE resource HREFs, IP addresses, label values, and any other tool parameters are not recorded. This prevents credential or PII leakage in the audit trail.
- **Confirm token payloads** — the `params_hash` (SHA-256 of canonical parameters) is recorded by the confirm endpoint, but not the parameters themselves.
- **PCE API responses** — the audit log records MCP-level decisions, not PCE-level results.
- **JWT contents** — only the `sub` and `iss` claims (which identify the user and IdP) are extracted.

---

## Correlation with X-Request-Id

Every HTTP request gets a UUID assigned by `RequestIdMiddleware` (or passed through if the client sends an `X-Request-Id` header). The audit log records this UUID in the `request_id` column.

To trace a specific call end-to-end:

1. Find the `request_id` in the audit log (e.g., from a user complaint).
2. Search your HTTP server logs (uvicorn) for that UUID to find the exact HTTP timing and client IP.
3. If PCE returned an error, the error text is in the tool's JSON response which is logged by the handler.

---

## Retention strategy

The audit database is a local SQLite file. For compliance environments, ship it to a SIEM.

**Option A: Cron-based purge (simplest)**

```bash
# Purge entries older than 90 days (run from cron daily)
sqlite3 /var/lib/illumio-mcp/audit.db \
  "DELETE FROM audit_log WHERE ts < datetime('now', '-90 days');"
sqlite3 /var/lib/illumio-mcp/audit.db "VACUUM;"
```

**Option B: Fluent Bit tail to SIEM**

If you run Fluent Bit, you can tail the SQLite file by periodically dumping new rows to a JSON file that Fluent Bit tails:

```bash
# Dump new rows since last checkpoint (adjust offset tracking as needed)
sqlite3 /var/lib/illumio-mcp/audit.db \
  "SELECT json_object('ts',ts,'sub',sub,'tool',tool,'decision',decision,'reason',reason,'role',role,'request_id',request_id) \
   FROM audit_log WHERE id > $LAST_ID ORDER BY id;" \
  >> /var/log/illumio-mcp-audit.jsonl
```

Then configure Fluent Bit to tail `/var/log/illumio-mcp-audit.jsonl` and forward to your SIEM (Splunk, Elastic, etc.).

**Option C: Separate audit path (future)**

A future release may add a structured JSON log stream that is easier to tail without SQLite tooling. Until then, the SQLite dump approach is the recommended path.
