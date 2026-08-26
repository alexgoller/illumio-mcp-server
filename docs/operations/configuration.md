# Configuration Reference

Every environment variable the server understands. In stdio mode only the first group applies. All other groups are for HTTP deployments.

---

## Stdio + shared PCE credentials

These are the PCE connection settings used by stdio mode and by HTTP shared mode (`MCP_PCE_MODE=shared`).

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `PCE_HOST` | Always (stdio or shared HTTP) | — | URL | `https://pce.example.com` |
| `PCE_PORT` | Always | — | Integer | `8443` |
| `PCE_ORG_ID` | Always | — | Integer | `1` |
| `API_KEY` | Always | — | String | `api_key_abc123` |
| `API_SECRET` | Always | — | String | `secret_xyz...` |
| `PCE_TLS_VERIFY` | Optional | `true` | `true` or `false` | `false` (disable for self-signed cert) |

---

## HTTP transport

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_HTTP_HOST` | Optional | `127.0.0.1` | IP or hostname | `0.0.0.0` |
| `MCP_HTTP_PORT` | Optional | `8080` | Integer | `443` |
| `MCP_DEV_INSECURE` | Never in production | unset | `1` | `1` |

`MCP_DEV_INSECURE=1` disables all auth, skips OAuth config validation, and allows binding non-loopback addresses. The server logs a prominent warning. Never set this in production.

---

## OAuth Resource Server

Required for all authenticated HTTP deployments (i.e., any deployment where `MCP_DEV_INSECURE` is not set).

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_OAUTH_ISSUER` | HTTP auth mode | — | URL | `https://login.microsoftonline.com/<tid>/v2.0` |
| `MCP_OAUTH_JWKS_URL` | HTTP auth mode | — | URL | `https://login.microsoftonline.com/<tid>/discovery/v2.0/keys` |
| `MCP_OAUTH_AUDIENCE` | HTTP auth mode | — | String | `https://mcp.illumio.example` |
| `MCP_OAUTH_REQUIRED_SCOPE` | Optional | `illumio-mcp.use` | String | `illumio-mcp.use` |
| `MCP_PUBLIC_URL` | HTTP auth mode | — | URL | `https://mcp.illumio.example` |

`MCP_PUBLIC_URL` is the public-facing URL of this server, used in the RFC 9728 Protected Resource Metadata document (`/.well-known/oauth-protected-resource`). It must match the `resource_url` field MCP clients expect.

---

## PCE mode and keystore

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_PCE_MODE` | Optional | `per_user` | `per_user` or `shared` | `shared` |
| `MCP_KEK` | `MCP_PCE_MODE=per_user` and auth mode | — | Base64 of 32 random bytes | (generate — see below) |
| `MCP_KEYSTORE_PATH` | Optional | `./data/keys.db` | File path | `/var/lib/illumio-mcp/keys.db` |

The `MCP_KEK` (Key-Encryption-Key) encrypts the per-user PCE secrets at rest. It is never stored in the SQLite database. Loss of `MCP_KEK` means all per-user credentials are permanently unrecoverable (intentional, fail-closed). In production, source it from KMS or Vault rather than a shell export.

---

## Role mapping

Configure which IdP groups grant which MCP roles. Users are granted the highest role that any of their groups qualifies for.

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_ROLE_GROUPS_ADMIN` | Recommended | — | Comma-separated group names | `sg-illumio-mcp-admin` |
| `MCP_ROLE_GROUPS_OPERATOR` | Recommended | — | Comma-separated group names | `sg-illumio-mcp-operator,sg-illumio-mcp-admin` |
| `MCP_ROLE_GROUPS_READER` | Recommended | — | Comma-separated group names | `sg-illumio-mcp-readonly,sg-illumio-mcp-operator,sg-illumio-mcp-admin` |
| `MCP_ROLE_DEFAULT` | Optional | unset (refuse) | `reader`, `operator`, or `admin` | `reader` |

If `MCP_ROLE_DEFAULT` is unset and a user's JWT groups match none of the configured lists, the user receives a `forbidden_no_role` error and the call is denied.

---

## Diagnostic logging

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_LOG_LEVEL` | Optional | `INFO` | Python log level name | `DEBUG` |

Controls the level of the `illumio_mcp` diagnostic log. Case-insensitive. An
unrecognised value falls back to `INFO` and warns **on stderr** -- the warning is
emitted before the file handler is attached, so it does not appear in the log
file itself. `NOTSET` is rejected rather than honoured: it means "defer to the
parent", which with `propagate=False` resolves to `WARNING`, quieter than the
documented floor.

The log path is `./illumio-mcp.log` (the working directory) unless the
`DOCKER_CONTAINER` environment variable is set, in which case it is
`/var/log/illumio-mcp/illumio-mcp.log`. The container image sets it; a container
started without it writes to the working directory instead.

**Leave this at `INFO` in production.** At `DEBUG` the tool handlers echo the
full arguments of every call. Sensitive values (`api_key`, `api_secret`,
`confirm_token`) are redacted before they reach the log, but the remaining
payload still describes your policy and workload topology in detail, and the
log file is long-lived on disk. `DEBUG` should be a deliberate, temporary
choice while diagnosing a problem.

This is a separate concern from MCP protocol logging: the server never sends
`notifications/message` to clients.

---

## Audit log

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_AUDIT_LOG_PATH` | Optional | Derived from `MCP_KEYSTORE_PATH` | File path | `/var/lib/illumio-mcp/audit.db` |

Default path is `<keystore_directory>/audit.db`. If `MCP_KEYSTORE_PATH` is also unset, defaults to `./data/audit.db`.

---

## Confirm tokens

Required for HTTP auth mode (the server refuses to start without `MCP_CONFIRM_HMAC_KEY` when auth is enabled).

| Var | Required when | Default | Format | Example |
|---|---|---|---|---|
| `MCP_CONFIRM_HMAC_KEY` | HTTP auth mode | — | Base64 of 32 random bytes | (generate — see below) |
| `MCP_CONFIRM_TTL_SECONDS` | Optional | `120` | Integer | `300` |
| `MCP_CONFIRM_JTI_PATH` | Optional | Derived from keystore dir | File path | `/var/lib/illumio-mcp/jti.db` |
| `MCP_CONFIRM_FRESH_AUTH_SECONDS` | Optional | unset | Integer | `300` |

`MCP_CONFIRM_FRESH_AUTH_SECONDS` requires the JWT's `auth_time` claim to be within this many seconds of the `/confirm` request. When set, the user must have re-authenticated recently before they can mint a confirm token — the strongest prompt-injection defense. Requires the IdP to issue `auth_time` (Entra and Okta do for OIDC flows).

---

## Generate all the secrets at once

```bash
echo "MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')"
echo "MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')"
```

Store the output in your secrets manager or KMS. Never commit these values to version control.
