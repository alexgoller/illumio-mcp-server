# Changelog

Notable changes to the Illumio MCP server.

This file is **read by the server itself**. A long-running MCP session caches
`tools/list` at connect time and forms assumptions about how tools behave from
the responses it has seen. When the server is updated underneath it, neither the
cache nor those assumptions are refreshed — the session keeps calling tools the
old way and silently gets different answers.

So a session can ask, without reconnecting:

- tool `get-server-changelog` — what changed, optionally `since` a version
- resource `illumio://changelog` — the same content for resource-reading clients

Each release lists **Unlearn** entries: assumptions a session formed against an
earlier build that are now wrong. Those matter more than the feature list —
a new tool is discoverable, a changed contract is not.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] — 2026-09-18

### Fixed

- **The public-bind guard was inverted, and it disabled the security stack.**
  The server refused any non-loopback bind unless `MCP_DEV_INSECURE=1` — the flag
  that turns authentication *off*. Serving a network interface therefore meant
  serving it unauthenticated, making the entire OAuth, keystore, RBAC and confirm
  stack unreachable in the deployment it exists for. Now: `0.0.0.0` **with** auth
  is allowed; `0.0.0.0` with `MCP_DEV_INSECURE=1` is refused.
- **`used_jti` really did grow forever.** `purge_expired` existed with no callers,
  so it deleted nothing for the life of the process — one row per consumed
  confirm token, indefinitely. Now runs opportunistically on write, rate-limited
  to once every 5 minutes, and failure is non-fatal.

### Documentation

- `docs/security-model.md` "Known gaps" rewritten from **verification against the
  code**, not carried forward. Three entries were stale (closed in 0.6.0), two
  were genuinely open and are now fixed, and the remaining open items say why
  they stay open.
- README: the feature list now reflects the last week's work, and the
  prerequisites said **Python 3.8+** where `pyproject.toml` requires `>=3.12`.
- Tool counts corrected from 46 to 50 across the docs site.
- First git tags and GitHub release: v0.2.0 … v0.6.0 tagged at the commits where
  each version was actually current; v0.6.0 published as a release.

### Unlearn

- **`MCP_DEV_INSECURE=1` no longer permits a public bind.** If you were relying
  on it to serve `0.0.0.0`, that combination is now refused — configure auth, or
  bind loopback.

---

## [0.6.0] — 2026-09-18

### Security

Closes the four findings left open by the 2026-05-13 review.

- **Security headers on every response** — `Content-Security-Policy:
  default-src 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options`,
  `Referrer-Policy: no-referrer`.
- **`Cache-Control: no-store` on `/setup` and `/confirm`.** `/confirm` returns a
  single-use token with a 120s TTL; a shared browser profile or proxy that
  cached it could replay it inside that window.
- **Per-subject rate limiting** — `/confirm` 10/min, `/mcp` 60/min, tunable via
  `MCP_RATE_LIMIT_CONFIRM` / `MCP_RATE_LIMIT_MCP`. Keyed by JWT `sub`, not IP:
  a whole office behind one NAT shares an IP. *Per-process, so N workers means
  N× the ceiling — exact for the single-process Docker image.*
- **SSRF guard on `pce_host`**, plus `register-pce-credentials` restricted from
  ALL_ROLES to operator/admin. Blocks loopback, link-local (cloud metadata at
  `169.254.169.254` is the real target), unspecified, multicast and reserved.
  **Deliberately allows RFC1918**: an on-prem PCE lives there by design, and the
  review's "block private ranges" advice would break most real deployments.
  `MCP_ALLOWED_PCE_HOSTS` gives a strict allowlist where that is wanted.
- Also **`X-Request-Id` sanitised** — the last MEDIUM. Hostile values are
  discarded for a fresh UUID; clean ones survive for correlation.

Not closed: DNS rebinding. Addresses are validated at registration; a name that
resolves differently later is not caught. Fixing it needs pinning the resolved
address, which the Illumio SDK does not expose. Use the allowlist where it
matters.

### Changed

- **Destination attribution: 4 providers / 30 ranges → 13 / 2,869.** Microsoft
  365 split by service area (Exchange, SharePoint, Skype), selected AWS services
  (S3, CloudFront, API Gateway), and Google Cloud. All `ambiguous`: shared
  infrastructure identifies a platform, never a tenant.
- **Lookup is now longest-prefix over prefix-length buckets, not a linear scan.**
  Measured: the scan cost 36 ms per 8,000-row summary at 30 ranges and projected
  to ~6 seconds at 5,000. The matcher does 2,869 ranges in 22 ms — faster than
  the old table 95× smaller.

### Unlearn

- **Overlapping ranges are now correct, not a bug.** `20.20.32.0/19` (Microsoft
  365) beats `20.0.0.0/8` (Azure), so a destination inside both reports the more
  specific claim. The old "no overlaps" rule was only valid while lookup was a
  linear scan; three tests asserting it were replaced.
- **`register-pce-credentials` now needs operator or admin.** A reader account
  can no longer make the server connect to a host it chooses.
- **Stored `pce_host` is normalised** — `https://pce.example:8443` is stored as
  `pce.example`, matching what the Illumio SDK actually dials, so status now
  reports the host the server will really connect to.
- **`/confirm` and `/mcp` can return 429** with `Retry-After`. Honour it rather
  than retrying immediately.

---

## [0.5.0] — 2026-09-17

### Changed

- **Traffic tools that aggregate now query the PCE wide.** `MCP_QUERY_MAX_RESULTS`
  (200,000) is separate from `MCP_BUG_MAX_RESULTS` (500). The 500 was always a
  *response*-size limit; using it as a *query* limit meant every summary was
  computed from the first 500 rows the PCE returned. Measured on demo100: a
  30-day whole-estate window is ~8,000 Explorer rows, so summaries described 6%
  of the window — and not a representative 6%.
- The summary now spends its response budget on aggregated tuples, widest first,
  instead of cutting every section to 5. The same 30-day estate returns complete
  at ~340 KB of the 800 KB budget.
- `app_to_app` groups on **app+env identity**, not workload hostname. It was
  documented as "the coarse app-to-app view" but grouped on a label that prefers
  hostname, so it returned 1,394 host pairs where the app view is 351.

### Added

- `identity_labels` on `get-traffic-flows-summary`: the label dimensions that
  define an endpoint in `app_to_app`. Defaults to `["app","env"]`, but any
  dimension the PCE defines works — `["bu"]`, `["compliance","env"]`,
  `["role","loc"]`. demo100 alone has 15 dimensions in use.
- `group_by` reaches every label dimension as `source_<label>` /
  `destination_<label>`, case-insensitively. Eight dimensions present in the
  flow data were previously unreachable by name.
- `available_dimensions` in the summary response lists what this PCE actually
  has, so callers need not guess.
- `detail_level` on `get-traffic-flows-summary`: `"standard"` (default, top 100
  per section) or `"full"`. Fitting inside the response limit is not the same as
  being worth sending, so the default trims the display, never the arithmetic.
- `section_totals` on the summary: the full count of every section, regardless of
  how many are shown.
- `truncated_sections` + `truncation_note` naming exactly what was trimmed.

### Unlearn

- **`truncated: true` on a summary no longer means "we only looked at 500 rows".**
  It now means the whole window was analysed and the *display* was trimmed.
  Counts from earlier sessions are not comparable — they were computed from a
  fraction of the window.
- **`app_to_app` entries are apps, not hosts.** `{"from": "laptop (Users)"}`, not
  `{"from": "pay-web01-prd"}`. Anything matching hostnames there will stop.
  External endpoints appear as `external:<fqdn>`.
- **Read `section_totals`, not the array length**, to know how much exists. A
  section array is a display slice; its length never meant "this is all there is".
- Summaries take longer now (~10s for 30 days on a mid-size estate) because they
  read the whole window. That is the query doing its job, not a hang.
- **Responses are larger**: ~28k tokens at the default `detail_level="standard"`,
  up from ~8k. `detail_level="full"` is ~87k. Both analyse the whole window --
  only the displayed rows differ, and `totals`/`section_totals` are identical
  between them.
- **`get-traffic-flows` is unchanged.** If you want raw flow rows it is still the
  tool, still capped at 500. Narrow the query rather than asking for more rows.

### Fixed

- **Standard (non-selective) ringfences were broken on main.** 0.4.0 scoped the
  All Services lookup to selective runs, but the intra-scope and extra-scope
  ALLOW rules are built from it too, so a standard ringfence fell through to the
  port -1 fallback and the PCE answered `Invalid value -1 - must be integer
  between 0 and 65535`. The lookup now happens for every ringfence; only the
  `deny_service` override remains selective-only.

---

## [0.4.0] — 2026-09-16

### Added

- `create-service` / `update-service` accept `windows_services` and
  `windows_egress_services`, so a service can be qualified by process.
  `service_ports` is no longer required.
- `get-services` returns `windows_egress_services` and filters on
  `egress_process_name`.
- Rule tools take service references: `{"href": ...}` or
  `{"service": "All Services"}` alongside inline `{"port", "proto"}`.
- `update-sec-rule` and `delete-sec-rule` — allow rules can be changed in place
  instead of rebuilding the ruleset.
- `egress_services` on `create-ruleset` rules and `update-sec-rule`: the
  consumer-side process qualifier.
- `create-ringfence` takes `deny_service` (default `All Services`).

### Fixed

- Rule tools rebuilt every `ingress_services` entry as `{port, proto}`, silently
  DISCARDING an `href`. The call succeeded and the PCE stored `0/tcp` — a rule
  that looked like policy and was not. Unknown and conflicting keys are now hard
  errors and nothing is sent until every entry resolves.
- Service names resolve exactly. The PCE matches `?name=` as a substring, so
  `S-HTTP` also returns `S-HTTPS` and `S-HTTPS-UDP`.

### Unlearn

- **`ingress_services` no longer silently accepts a mixed entry.**
  `{"port": 0, "proto": "tcp", "href": "..."}` is now rejected naming both
  fields. Anything that relied on the href being ignored will stop.
- **`{"port": 0}` never meant "all ports".** For any service use
  `{"service": "All Services"}`; an empty list is rejected by the PCE.
- **A service object carries an OS type, and the three qualifier lists are
  mutually exclusive.** Supplying `service_ports` with `windows_*` made the PCE
  keep one, null the others, and still return 201. That combination is now
  refused up front — so "chrome.exe on 443" is NOT one service object.
- **`windows_egress_services` takes `process_name`/`service_name` only.** The
  PCE rejects `port`/`proto` there. The port belongs on the rule.
- **A Windows egress service cannot go in `ingress_services`.** It belongs in
  the rule's `egress_services`, which qualifies the consumer's process while
  `ingress_services` stays the provider-side port. The two together express
  "this binary, to that port".
- Deny rules cannot use process-qualified services at all; write a qualified
  allow above a broad deny.

---

## [0.3.0] — 2026-09-15

### Changed

- **Destination attribution is now derived from RDAP**, not hand-written.
  `scripts/refresh_ip_ranges.py` regenerates `src/illumio_mcp/data/ip_ranges.json`
  weekly in CI. The server performs no network I/O for attribution — it reads
  the shipped table and does offline CIDR containment.
- Attribution ranges gained IPv6 coverage and now compile once at import.

### Fixed

- `anthropic` was `160.79.104.0/23`; ARIN allocates `160.79.104.0/21`. Claude
  traffic outside the narrower block was reported as unattributed.
- Three ranges shipped as `openai` with `likely` confidence are registered to
  **Microsoft Corporation** — Azure-hosted OpenAI endpoints, shared with other
  tenants. Now reported as `azure-hosted` / `ambiguous`.

### Unlearn

- `classify_destination` no longer returns `openai`. Traffic to
  `23.102.140.112/28`, `13.66.11.96/28` and `104.210.133.240/28` now reports
  `azure-hosted` / `ambiguous`. **Do not tell a user "OpenAI" for those** — the
  registry does not support that claim.
- Only `provider_confidence: "likely"` identifies a vendor. `ambiguous` means
  shared infrastructure (Cloudflare fronts both Anthropic and OpenAI;
  `20.0.0.0/8` is all of Azure). Reporting an `ambiguous` hit as a vendor
  produces false positives.

---

## [0.2.0] — 2026-09-15

### Added

- `discover-process-egress` reports `likely_provider` and `provider_confidence`
  per finding, plus a `providers` rollup.
- Traffic summary reports `raw_observations` from the PCE async query status.
- `get-workloads`, `create-ringfence` and the traffic tools accept any label
  reference form via the shared `label_refs` module.

### Changed

- **Every mutating tool's description now warns that the client will pause for
  approval.** Derived from `TOOL_REGISTRY`, so it cannot drift.
- Ringfence discovery pulls up to 100000 flows instead of 500, and reports
  `flows_analysed` plus a warning when discovery saturates.

### Fixed

- `get-workloads` returned HTTP 406 `invalid_uri` for any label filter. The
  `labels` parameter needs a JSON string of nested lists; the raw list was
  passed through.
- The egress flow cap applied **before** the process filter, so requested
  processes could fall outside the window entirely. Now filtered server-side.
- Egress grouped on the full process path, so one binary under eight user
  profiles counted as eight processes.

### Unlearn

- **A stalled write tool is probably an approval prompt, not a hung server.**
  Do not retry — that queues a second approval for a PCE write.
- `truncated` no longer exists on egress results. It conflated two different
  problems and is replaced by:
  - `findings_truncated` — report trimmed for size; the rest is one call away.
  - `flows_truncated` — the PCE never returned the whole picture, so **the
    counts shown are lower bounds**. Only this one means distrust the answer.
- Label arguments no longer require HREFs. `app=ordering`,
  `/orgs/1/labels/42`, `{"key": "app", "value": "ordering"}` and
  `{"href": "..."}` are all accepted everywhere. An unrecognised label now
  **fails with `unresolved_label_filter`** rather than being dropped — a
  dropped label silently widened the filter and answered a different question.
- Egress findings key `process` on the basename now (`Claude.exe`), with no
  per-user path. Counts of "distinct processes" from earlier sessions are not
  comparable.

---

## [0.1.0] — earlier

Initial tool surface: workloads, labels, services, IP lists, rulesets, deny
rules, ringfencing, traffic analysis, container profiles, and the HTTP transport
with OAuth, RBAC and audit logging.
