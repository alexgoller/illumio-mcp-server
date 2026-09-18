---
title: Security model
layout: default
nav_order: 10
---

# Security model
{: .no_toc }

1. TOC
{:toc}

---

This server can change firewall policy. The controls below only exist in **HTTP mode**;
stdio mode has none of them by design.

## Layers

| Layer | Mechanism |
|---|---|
| Authentication | OAuth 2.0 Resource Server. JWTs validated against the IdP's JWKS (RS256/ES256), requiring `exp`, `iat`, `iss`, `aud`, `sub`, with the audience bound to this resource |
| Discovery | RFC 9728 Protected Resource Metadata at `/.well-known/oauth-protected-resource`; `401` responses carry a `WWW-Authenticate` pointer to it |
| Authorization | Roles from IdP group membership — `admin > operator > reader` — enforced per tool |
| Human gate | Single-use HMAC confirmation tokens on the two policy-changing tools |
| Credential storage | AES-256-GCM envelope encryption, per-record data keys, bound to the user's identity |
| Audit | Every tool decision recorded with the human's identity |

## The confirmation gate

`provision-policy` and `ringfence-batch` require a second step. `POST /confirm` mints a
token that is:

- **integrity protected** — HMAC-SHA256
- **bound to the caller** — carries their `sub`
- **short-lived** — 120 s by default (`MCP_CONFIRM_TTL_SECONDS`)
- **bound to the exact call** — carries the tool name and a hash of the arguments
- **single-use** — a `jti` table rejects replay

Argument binding is the important property: approval obtained for one policy push cannot
be reused for a different one.

{: .note }
> **What this is, today.** The MCP client obtains the token itself using the same bearer
> token it already holds. So the gate proves an authenticated second round-trip, not
> human intent. `MCP_CONFIRM_FRESH_AUTH_SECONDS` adds a step-up requirement against the
> JWT's `auth_time` claim. Genuine human-in-the-loop confirmation needs MCP elicitation,
> which arrives with the 2026-07-28 protocol revision.

## Secret handling

Sensitive values — `api_key`, `api_secret`, `confirm_token` — are recursively redacted
before anything is logged, wherever they appear in the argument payload. The redaction is
enforced by a test that fails if any handler serialises arguments without it.

Diagnostic logging defaults to `INFO`. `DEBUG` echoes full tool arguments; the secrets
above stay redacted, but the remaining payload describes your policy and workload
topology in detail, and the log is long-lived on disk.

## Threat model and review

- [Threat model](security/threat-model)
- [Architecture](security/architecture)
- [Secret management](security/secret-management)

## Known gaps

Verified against the code on 2026-09-18, not copied forward from the last review.

| Gap | Status |
|---|---|
| No request-rate limiting | **Closed** in 0.6.0 — per-subject token bucket, `/confirm` 10/min, `/mcp` 60/min |
| No `Cache-Control: no-store` on `/setup` and `/confirm` | **Closed** in 0.6.0 |
| `X-Request-Id` accepted from the client unsanitised | **Closed** in 0.6.0 — hostile values discarded for a fresh UUID |
| Missing HTTP security headers | **Closed** in 0.6.0 — CSP, `X-Frame-Options`, nosniff, `Referrer-Policy` |
| SSRF via user-supplied `pce_host` | **Closed** in 0.6.0 — see below for what is deliberately still allowed |
| `jti` table grows unboundedly (`purge_expired` never called) | **Closed** in 0.7.0 — the method existed with no callers; now runs opportunistically on write |
| Public bind and authentication mutually exclusive | **Closed** in 0.7.0 — the guard was inverted; see below |
| Confirmation gate does not prove *human* intent | **Open, by design today** — see the note above |
| DNS rebinding against `pce_host` | **Open** — addresses are validated at registration; a name that resolves differently later is not caught |
| Rate limiting is per-process | **Open by design** — N workers multiply the ceiling; exact for the single-process image |

### The bind guard was backwards

Before 0.7.0 the server refused any non-loopback bind unless `MCP_DEV_INSECURE=1`
— and that flag is precisely what turns authentication off. The only way to
serve a network interface was therefore to serve it **unauthenticated**, which
made the whole OAuth, keystore, RBAC and confirm stack unreachable in exactly
the deployment it exists for.

It now works the way round it always should have:

| Bind | Auth configured | Result |
|---|---|---|
| `127.0.0.1` | either | allowed |
| `0.0.0.0` | yes | **allowed** — the production case |
| `0.0.0.0` | no (`MCP_DEV_INSECURE=1`) | **refused** — the genuinely dangerous combination |

### What the SSRF guard deliberately allows

RFC1918 addresses are accepted, because an on-prem PCE lives there by design and
a guard that breaks the normal deployment gets switched off. Blocked: loopback,
link-local (cloud instance metadata), unspecified, multicast and reserved. Set
`MCP_ALLOWED_PCE_HOSTS` for a strict allowlist.

Request body size is capped at 4 MiB by the MCP SDK. Dependencies are checked against OSV
and currently carry no known advisories.

## Reporting

Security issues: open a GitHub issue marked security, or contact the maintainer directly
for anything sensitive.
