---
title: Secret management
layout: default
parent: Security
---

# Secret Management

How each secret should be generated, stored, and rotated.

---

## `MCP_KEK` — Key-Encryption-Key

**What it protects:** All per-user PCE API keys and secrets stored in the keystore SQLite database. Without the KEK, the database is unreadable.

**Generate:**

```bash
python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'
```

This produces a 32-byte (256-bit) base64-encoded key, e.g.:
`7K9mLqR3XpWvNzYeHcJbFdUsGtAiOk1s2PlMnQrEhVyw4BxCuDf5T6gZ8jO0sIA=`

**Store:**
- Development: in `.env` (never committed).
- Production: in AWS KMS, HashiCorp Vault, Azure Key Vault, or a Kubernetes Secret with appropriate RBAC. The KEK value should never appear in version control or logs.
- The server reads it from the process environment as a base64 string. Inject it from your secrets manager at deploy time.

**Rotate:**

KEK rotation re-wraps data keys without re-encrypting the payloads:

1. Generate a new KEK.
2. For each row in `user_pce_credentials`: decrypt the old `api_key_enc` and `api_secret_enc` using the old KEK, re-encrypt with the new KEK.
3. Update the env var (`MCP_KEK`) to the new value.
4. Restart the server.

Step 2 is not yet implemented as a built-in command (future work). For now, perform it with a migration script using the `EnvelopeCipher` class from `src/illumio_mcp/auth/crypto.py`:

```python
from illumio_mcp.auth.crypto import EnvelopeCipher, load_kek_from_env
import base64, os, sqlite3

old_kek = base64.b64decode(os.environ["OLD_MCP_KEK"])
new_kek = base64.b64decode(os.environ["NEW_MCP_KEK"])
old_cipher = EnvelopeCipher(old_kek)
new_cipher = EnvelopeCipher(new_kek)

with sqlite3.connect("./data/keys.db") as con:
    rows = con.execute("SELECT sub, iss, api_key_enc, api_secret_enc FROM user_pce_credentials").fetchall()
    for sub, iss, api_key_enc, api_secret_enc in rows:
        aad = f"{sub}|{iss}".encode()
        ak = old_cipher.decrypt(api_key_enc, aad=aad)
        ase = old_cipher.decrypt(api_secret_enc, aad=aad)
        new_ak_enc = new_cipher.encrypt(ak, aad=aad)
        new_ase_enc = new_cipher.encrypt(ase, aad=aad)
        con.execute(
            "UPDATE user_pce_credentials SET api_key_enc=?, api_secret_enc=? WHERE sub=? AND iss=?",
            (new_ak_enc, new_ase_enc, sub, iss),
        )
```

**Loss consequence:** All per-user PCE credentials become permanently unrecoverable. Users must re-register. This is intentional (fail-closed).

---

## `MCP_CONFIRM_HMAC_KEY` — Confirm token signing key

**What it protects:** The integrity of confirm tokens. An attacker who knows this key could mint valid confirm tokens for any user and tool.

**Generate:**

```bash
python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'
```

**Store:** Same guidance as `MCP_KEK` — secrets manager, never in version control.

**Rotate:**

1. Generate a new HMAC key.
2. Update the env var (`MCP_CONFIRM_HMAC_KEY`) to the new value.
3. Restart the server.

**Effect of rotation:** All outstanding confirm tokens (those minted with the old key) become immediately invalid. Users in the middle of a multi-step operation will need to mint a new token. Because tokens expire in `MCP_CONFIRM_TTL_SECONDS` (default 120s), the impact window is small.

---

## `API_KEY` / `API_SECRET` — Shared PCE service account credentials

Used in stdio mode and HTTP shared mode (`MCP_PCE_MODE=shared`).

**Rotation in shared mode:**

1. Generate a new PCE API key for the service account in the PCE admin UI.
2. Update `API_KEY` and `API_SECRET` in the env.
3. Restart the HTTP server. The new credentials take effect immediately — the `get_pce_from_env()` function re-reads env vars on the next restart (it caches after first call within a process lifetime).
4. Delete the old PCE API key from the PCE admin UI.

**Rotation in stdio mode:** Same steps; each MCP client process will pick up the new credentials on next launch.

---

## Per-user PCE credentials (keystore)

Each user's PCE API key and secret are stored encrypted in the keystore. Users manage their own credentials.

**Self-service rotation:**

1. Generate a new PCE API key in the PCE admin UI.
2. Call `register-pce-credentials` with the new values — it overwrites the existing row (using SQLite `INSERT ... ON CONFLICT DO UPDATE`).
3. Or visit `/setup` and submit the new values.

The old PCE API key can then be deleted from the PCE admin UI.

**Admin-forced rotation:**

An admin can delete a specific user's credentials by calling `delete-pce-credentials` (requires `admin` role) or by direct SQLite manipulation:

```sql
DELETE FROM user_pce_credentials WHERE sub = '<user-sub-from-idp>';
```

After deletion, the user's next tool call will return `no_pce_credentials` and they will need to re-register.

---

## Audit log — what to ship to SIEM

The audit log contains no secrets (tool arguments are not logged, PCE credentials are never logged). It is safe to ship to your SIEM without further redaction.

Sensitive columns that ARE present:
- `sub` — the IdP subject identifier (a user ID, not a display name). Map to display names in your SIEM using IdP directory data.

Ship strategy: see the [Audit Log operations guide](../operations/audit-log.md) for Fluent Bit and cron-based options.

---

## Generate all secrets at once

```bash
echo "MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')"
echo "MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')"
```

Store the output immediately in your secrets manager. Do not save it to a shell history or a text file.
