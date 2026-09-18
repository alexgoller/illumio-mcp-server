# Close the four open security-review findings

Source: docs/security/2026-05-13-security-review.md (v0.2.0 review).
Verified still open in current code before starting.

## Plan

- [x] 1. SecurityHeadersMiddleware — X-Content-Type-Options, X-Frame-Options,
      CSP, Referrer-Policy on every response.
- [x] 2. Cache-Control: no-store on /setup and /confirm (same middleware —
      they are the same concern: what a response is allowed to leak onward).
- [x] 3. Per-subject rate limiting: /confirm 10/min, /mcp 60/min.
- [x] 4. SSRF guard on the user-supplied pce_host.
- [x] 5. (adjacent, 3 lines) Sanitise client-controlled X-Request-Id — the last
      MEDIUM in the review, in a file item 1 already touches.
- [x] 6. Tests + full suite + update the review with a status column.

## The one real design trap

**Illumio PCEs are frequently on-prem, on RFC1918 addresses.** The review says
"validate the hostname is not a loopback/link-local/private-range address".
Blocking private ranges outright would break every legitimate on-prem
deployment — the majority of real Illumio installs.

So the guard must block what is actually dangerous without breaking the normal
case:

  BLOCK  loopback, link-local (169.254.0.0/16 — cloud metadata at
         169.254.169.254 is the real prize here), unspecified, multicast,
         reserved
  ALLOW  RFC1918, because that is where a real PCE lives
  OPT-IN MCP_ALLOWED_PCE_HOSTS as a strict allowlist for operators who want one

That kills cloud-metadata SSRF, which is the finding's substance, while leaving
on-prem working.

## Rate limiting: no new dependency

The review suggests slowapi. An in-process token bucket keyed by JWT `sub` is
~40 lines and avoids a dependency in a server people self-deploy. Honest
caveat to document: per-process, so a multi-worker deployment multiplies the
effective limit. Stated in the docs rather than hidden.

## Review

All five findings closed (the four asked for, plus the adjacent X-Request-Id
MEDIUM). Suite: 568 passed, 1 skipped, 0 failed.

### The design call that mattered

The review said to reject "loopback/link-local/private-range". Blocking RFC1918
would break most real Illumio deployments -- an on-prem PCE lives there by
design -- and a guard that breaks the normal case gets switched off. Blocked
what is actually dangerous (loopback, link-local/cloud-metadata, unspecified,
multicast, reserved), allowed RFC1918, and added MCP_ALLOWED_PCE_HOSTS for
operators who want strictness.

### A design error I made and corrected

The first cut treated DNS resolution failure as fatal. That broke per-user
credential registration entirely -- 7 suite failures -- because test and real
hosts alike may not resolve from the server. It also bought no security: an
unresolvable name is not an SSRF target now, and if it resolves dangerously
later that is rebinding, which this approach never closed. Now: resolve and
validate what comes back, allow what does not resolve, and say so in the log.

### Scope that grew for a good reason

Expanding the IP attribution sources needed the lookup replaced first.
Benchmarked before writing anything: the linear scan cost 36ms per 8,000-row
summary at 30 ranges and projected to ~6 SECONDS at 5,000 -- it would have
doubled the cost of the aggregate-first work. The prefix matcher does 2,869
ranges in 22ms.

That also turned "no overlapping ranges" from an invariant into a mistake:
longest-prefix means Microsoft 365's /19 correctly beats Azure's /8. Three
tests asserting no-overlap were replaced with tests asserting the more specific
claim wins.
