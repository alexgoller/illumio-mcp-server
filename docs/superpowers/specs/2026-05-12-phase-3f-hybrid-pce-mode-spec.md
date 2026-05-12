# Phase 3f: Hybrid PCE Mode — Design Spec

**Status:** Backlog (feature request — not yet planned for implementation)
**Date:** 2026-05-12
**Depends on:** Phase 3b (per-user keystore) + Phase 3e (shared mode)
**GitHub issue:** _(linked when filed)_

---

## Problem

Phase 3b and Phase 3e introduced two PCE-credential modes that are mutually
exclusive at startup:

- `per_user` — every user must register their own PCE API key before any tool call works
- `shared` — every user uses the same operator-configured service-account key

Both have legitimate use cases, and some operators have asked for both at once:

- A team rolls out the MCP server in **shared** mode for fast onboarding
- A handful of senior engineers later want **per-user** PCE keys so PCE-side
  audit logs attribute actions to them by name
- Casual users keep getting "free" access through the shared key

Today they have to pick one and live with it. **Hybrid mode** lets the same
deployment serve both populations from one process.

## Proposed behavior

A new `MCP_PCE_MODE=hybrid` value:

| User has registered per-user creds? | What `ctx.pce` is built from |
|---|---|
| Yes | The user's encrypted creds in the keystore (per-user mode behavior) |
| No  | The env-loaded shared service account (shared mode behavior) |

Tool behavior in hybrid mode:

- **`/setup` is mounted** (users can opt into per-user attribution)
- **`register-pce-credentials`** works (writes to keystore, switches that user to per-user PCE)
- **`delete-pce-credentials`** works (drops them back to shared)
- **`check-pce-credentials-status`** returns one of:
  - `{"registered": true, "mode": "per_user", "pce_host": ..., ...}` — user has their own key
  - `{"registered": true, "mode": "shared", "message": "Using shared service account; call register-pce-credentials to opt into per-user attribution."}` — user falls back to shared

The dispatcher's `no_pce_credentials` gate **never fires** in hybrid mode — the
shared key is always available as a fallback.

## Why hybrid is non-trivial

Looks like a one-line `if pce is None: pce = get_pce_from_env()` — and it
mostly is — but there are real concerns the implementation must address:

1. **PCE-side audit ambiguity.** Some calls show up as the human, some as
   the service account. Whoever reads PCE audit needs to know this is by
   design, not a bug. Document loudly.

2. **Confused-deputy risk.** A user might *think* they're calling PCE as
   themselves but is actually using the shared key (because their stored key
   expired and silently fell back). Mitigation: `check-pce-credentials-status`
   should expose the *current* effective mode, and we should consider logging
   a per-call audit field `effective_pce_mode`.

3. **Audit-log schema bump.** Add `effective_pce_mode` column so operators can
   filter the audit log by which PCE creds were used: helpful for compliance
   reviews ("show me everything alice did with the shared key vs her own").

4. **Reading the shared key in hybrid mode requires the env vars.** Same
   refusal-to-start logic as Phase 3e: `MCP_PCE_MODE=hybrid` requires both
   `MCP_KEK` (for the keystore) AND `PCE_HOST`/`API_KEY`/`API_SECRET`
   (for the shared fallback). Failing fast saves a confusing runtime error.

## Sketch of implementation effort (when this is greenlit)

Approximately 5 tasks, roughly 1 day of work:

1. `auth/pce_mode.py` — add `HYBRID` constant, update `_VALID`, add
   `is_hybrid_mode()` helper.
2. `server.py` — `build_http_context_for` honors hybrid: per-user lookup
   first, then env-loaded fallback. Audit-log entry includes
   `effective_pce_mode` (`per_user` or `shared`).
3. `auth/audit.py` — add `effective_pce_mode` column to `audit_log` schema +
   a non-breaking migration.
4. `tools/credentials.py` — `check-pce-credentials-status` reports the
   current effective mode for the calling user; `register`/`delete` work as
   in per-user mode.
5. `transport/http.py` — load both `MCP_KEK` and `PCE_*` env in hybrid mode;
   mount `/setup` route.
6. Tests + README + PR.

The architecture from Phase 3 makes this clean: every authz layer (JWT,
role, audit, confirm) is independent of the PCE-credential source.

## When to build this

Don't build it speculatively. Triggers that justify shipping it:

- An operator has actually asked for it (not just a hypothetical)
- A team is using shared mode and wants a stepwise migration to per-user
- Compliance requires named attribution for a subset of users without
  forcing every user to onboard

Until one of those fires, leaving it as a documented spec is the right call.

## Decisions made up front (so future-us doesn't have to)

- Default behavior when key store has no row: **fall through to shared**, not
  refuse. Consistent with the "hybrid = best of both" promise.
- Keystore row removal is allowed (delete tool works) — it cleanly drops
  the user back to shared.
- `check-pce-credentials-status` reports the effective state as it would
  apply to the next tool call, not just whether a row exists.
- `MCP_PCE_MODE` is still resolved once at startup; you cannot switch a
  running process between hybrid and shared.

## Out of scope for this spec

- Per-user role overrides (Phase 3c handles role mapping; that's separate)
- Per-tool mode override (no use case yet for "this specific tool always
  uses the shared key even if the user has their own")
- Read-only fallback (some users could be allowed shared for reads but
  required to use their own key for writes — not asked for)
