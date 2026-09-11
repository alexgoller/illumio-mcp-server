---
title: Central deployment
layout: default
parent: Deployment
nav_order: 1
---

# Central deployment
{: .no_toc }

One server for a whole team: SSO, roles from group membership, per-user PCE credentials.
{: .fs-5 .fw-300 }

1. TOC
{:toc}

---

## The decision that shapes everything

`MCP_PCE_MODE` determines what your PCE audit log is worth. It is not a tuning knob.

| | `per_user` (default) | `shared` |
|---|---|---|
| PCE credentials | Each human registers their own, AES-256-GCM encrypted at rest | One service account from `PCE_*` env |
| PCE-side audit shows | The actual human | The service account, for everyone |
| PCE RBAC applies | Per human | Uniformly, at service-account level |
| Onboarding | User visits `/setup` once | None |
| Requires `MCP_KEK` | Yes | No |

`per_user` is the reason this transport exists — it makes *"alex@example.com deleted that
ruleset"* visible in Illumio's own logs rather than *"the MCP service account did it"*.
Choose `shared` only if you accept that attribution collapses. Either way, SSO, role
enforcement and the server-side audit log still record the real human.

## Two constraints to design around

{: .warning }
> **The server cannot bind a public interface with authentication enabled.**
>
> `serve_http(host="0.0.0.0")` exits with *"Refusing to bind '0.0.0.0' without
> MCP_DEV_INSECURE=1"*, and that flag forces the unauthenticated path — no OAuth, no
> keystore, admin role for everyone, no confirmation gate.
>
> So the TLS terminator **must share a network namespace** with the app: nginx or Envoy
> on the same host, or a sidecar in the same Kubernetes pod, reaching it over
> `127.0.0.1`. A reverse proxy on a different host cannot reach it.

{: .warning }
> **It is a single-instance service.** Three SQLite files hold state:
>
> | File | Contents | Variable |
> |---|---|---|
> | `keys.db` | Per-user PCE credentials | `MCP_KEYSTORE_PATH` |
> | `audit.db` | Who ran which tool | `MCP_AUDIT_LOG_PATH` |
> | `jti` table | Confirmation-token replay guard | `MCP_CONFIRM_JTI_PATH` |
>
> The MCP layer is stateless, so no session affinity is needed — the constraint is purely
> this state. Two replicas behind a load balancer would split the credential store and,
> worse, split the replay guard: a token spent on replica A could be replayed on replica
> B. Run **one instance with a persistent volume**.

## Request path

```
MCP client
  → TLS terminator (same host or pod)        HTTPS ends here
  → 127.0.0.1:8080
       RequestIdMiddleware                   X-Request-Id
       JWTAuthMiddleware                     RS256/ES256 against JWKS
                                             requires exp, iat, iss, aud, sub
                                             audience must equal this resource
       dispatcher                            groups → role → role gate
                                             → PCE gate → confirmation gate
  → PCE
```

Unauthenticated routes: `/healthz`, `/readyz`,
`/.well-known/oauth-protected-resource`. Everything else needs a bearer token.

## Configuration

```bash
# OAuth resource server — all required
MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
MCP_OAUTH_AUDIENCE=api://illumio-mcp
MCP_PUBLIC_URL=https://mcp.example.com      # must match what clients use
MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use

# Secrets — from a secrets manager, not env files
MCP_KEK=<32 bytes hex>                      # per_user mode only
MCP_CONFIRM_HMAC_KEY=<32 bytes hex>         # required whenever auth is on

MCP_PCE_MODE=per_user
MCP_ROLE_GROUPS_ADMIN=illumio-mcp-admins
MCP_ROLE_GROUPS_OPERATOR=illumio-mcp-operators
MCP_ROLE_GROUPS_READER=illumio-mcp-readers
# MCP_ROLE_DEFAULT=                         # leave unset: no group = no access

MCP_HTTP_HOST=127.0.0.1                     # see constraint above
MCP_LOG_LEVEL=INFO                          # DEBUG echoes full tool arguments
MCP_KEYSTORE_PATH=/var/lib/illumio-mcp/keys.db
DOCKER_CONTAINER=true
```

The server **fails closed** on all of these: missing OAuth configuration or
`MCP_CONFIRM_HMAC_KEY` is a startup error, not a silent degrade.

Full variable list: [Configuration](../operations/configuration).

## Roles

Roles come from the JWT `groups` (or `roles`) claim, highest wins —
`admin > operator > reader`.

| Tools | Minimum role |
|---|---|
| 22 read-only queries and reports | reader |
| 20 mutating operations | operator |
| 2 credential self-service | reader |
| **2 confirmation-gated** (`provision-policy`, `ringfence-batch`) | **admin** |

{: .caution }
> Leave `MCP_ROLE_DEFAULT` unset so an authenticated user with no mapped group gets
> nothing. Setting it to `reader` silently grants everyone in your directory read access
> to your segmentation topology.

## Onboarding a user (per_user mode)

1. Add the user to the appropriate IdP group.
2. They open `https://mcp.example.com/setup`, authenticate via SSO, and paste their own
   PCE API key and secret. It is stored envelope-encrypted under `MCP_KEK`, bound to
   their `sub` and `iss`.
3. They point their MCP client at `https://mcp.example.com/mcp`.

Before step 2, their tool calls return a clear `no_credentials` error.
`check-pce-credentials-status` is the self-service diagnostic.

## Operational checklist

- **Back up `keys.db`.** Losing it means every user re-registers. Losing `MCP_KEK` makes
  the backup unreadable — keep them in different failure domains.
- **The `jti` table grows unboundedly.** `purge_expired` exists but is never called.
  Schedule it or accept the growth.
- **Ship `audit.db` to your SIEM.** It is the record of who ran what.
- **Keep `MCP_LOG_LEVEL=INFO`.** At `DEBUG` the handlers echo full tool arguments;
  secrets are redacted, but the remainder describes your segmentation topology.
- **Scope the PCE service account** (shared mode) to the minimum RBAC the tools need.

## Further reading

- [Security model](../security-model)
- [HTTP mode reference](../operations/http-mode)
- [OAuth provider setup](../operations/oauth-providers)
- [Audit log](../operations/audit-log)
