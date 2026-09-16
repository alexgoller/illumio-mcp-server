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
