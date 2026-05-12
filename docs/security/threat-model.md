# Threat Model

What the Phase 1-3e design protects against, what it does not protect against, and the honest trade-offs operators need to understand before deploying.

---

## Threats mitigated

**Lost or stolen JWT (single user)**

If a user's access token is stolen, the attacker can call the MCP server until the token expires. Mitigation: the IdP can revoke the user's session (force a re-auth on the next token refresh). Token lifetime (`exp`) limits the exposure window. Setting `MCP_CONFIRM_FRESH_AUTH_SECONDS` for confirm-token operations forces a re-authentication before any destructive action, reducing the window further.

**Server compromise — encrypted credentials at rest**

If an attacker obtains the keystore database file (`keys.db`) without also obtaining `MCP_KEK`, the per-user PCE credentials are unreadable. The AES-256-GCM envelope encryption means the database file alone is not sufficient for decryption. `MCP_KEK` must be stored separately from the database (e.g., in KMS).

**Unauthenticated tool list discovery**

An unauthenticated client cannot enumerate MCP tools. `POST /mcp` without a valid `Authorization` header returns `401` with a `WWW-Authenticate` pointer to the PRM document — it does not reveal the tool list, server version, or any PCE details.

**Prompt injection forcing a destructive action**

The confirm-token requirement for `provision-policy` and `ringfence-batch` forces a synchronous human-in-the-loop step that the LLM cannot execute autonomously. Even if a malicious payload in a PCE traffic-flow description convinces the LLM to call `provision-policy`, the LLM cannot mint the confirm token — that requires a separately authenticated HTTP request to `POST /confirm`. With `MCP_CONFIRM_FRESH_AUTH_SECONDS` set, it also requires a recent re-authentication.

**Replay of a used confirm token**

Each confirm token's `jti` is recorded in the `used_jti` SQLite table on first use. A replay attempt returns `confirm_token_replay` before the token is consumed again.

---

## Risks and accepted trade-offs

**Lost `MCP_KEK` = total keystore loss**

This is intentional. The KEK must not be stored next to the database, so there is no recovery path if it is lost. Operators MUST store `MCP_KEK` in a durable secrets manager (KMS, Vault) before deploying in per-user mode. This is the "fail closed" design: a lost KEK is better than a KEK stored in a recoverable location that an attacker could find.

**Server compromise + KEK exfiltration = all per-user PCE keys readable**

If an attacker compromises the server process AND extracts `MCP_KEK` (from process memory or env), they can decrypt all stored per-user PCE credentials. The envelope encryption protects the database file at rest but does not protect against a fully-compromised process. Mitigations: minimize the attack surface of the server process, use KMS-backed KEK (so the plaintext KEK never leaves the KMS boundary), rotate PCE API keys on a schedule.

**No in-handler authz fallback**

The dispatcher enforces role, PCE-presence, and confirm-token checks before calling a handler. Handlers themselves do not re-check these. If a bug bypasses the dispatcher (e.g., via a future refactor that introduces a direct handler call path), handlers will execute without authz enforcement. Currently no such path exists, but it is a risk to be aware of in code review.

**Shared mode: server compromise = full PCE control as service account**

In `MCP_PCE_MODE=shared`, all authenticated users operate as the PCE service account. A server compromise gives the attacker full PCE API access as that service account. This is the same risk profile as the original stdio-only deployment, but now the service account is exposed over a network. Mitigate by: using a service account with minimal PCE RBAC permissions, rotating the PCE API key on a schedule, and preferring per-user mode where feasible.

**Streamable HTTP transport is not proxy-cache-safe**

`/mcp` responses use chunked SSE (server-sent events) for streaming tool results. Reverse proxies that buffer or cache SSE streams will break the protocol. Ensure your proxy sets `X-Accel-Buffering: no` (nginx) or equivalent, and does not apply response caching to `/mcp`. The RFC 9728 PRM endpoint (`/.well-known/oauth-protected-resource`) can be cached normally.

**MCP transport-level encryption is the proxy's responsibility**

The server binds HTTP only. TLS must be terminated at the reverse proxy. Running the server directly on a public network without TLS is insecure and is blocked by the loopback-only gate (which requires `MCP_DEV_INSECURE=1` to override).

---

## Out of scope

**Compromised IdP signing key**

If an attacker obtains the IdP's private signing key, they can forge JWTs that pass the server's validation. This is the IdP's security responsibility, not ours. We validate tokens against the JWKS endpoint; if the JWKS is poisoned, our validation is bypassed. Mitigate at the IdP level (short key rotation schedules, HSM-backed keys, JWKS endpoint integrity monitoring).

**PCE-side API vulnerabilities**

The MCP server is an API client to the PCE. Bugs in the PCE's API or authentication are out of scope. We use the `python-illumio` SDK and assume the PCE API is correctly implemented.

**Supply-chain attacks on Python dependencies**

No special mitigations beyond standard practice (pinned lockfile, private PyPI mirror). This is an operational concern for the deploying team.
