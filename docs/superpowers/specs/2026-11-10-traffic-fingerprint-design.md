# Traffic fingerprint and drift

**Status:** implemented in the same change (`get-traffic-fingerprint`).
**Date:** 2026-11-10

## Why

Large estates want a snapshot of an org's, environment's or app's traffic
shape they can keep and compare: "what changed in payments/prod since last
month", "is this environment stable", a per-app history. illumio-tui already
has three quarters of this: a traffic compare of a recent window against the
window before it (#77-80), local snapshots of policy, labels, workloads and
readiness (#84), and compare/trend over snapshots (#85). It has no stored
traffic baseline and nothing above the app pair. This is the missing piece,
built in the MCP server so a session can produce, keep and narrate it.

## Format (v1)

One JSON object, `fingerprint_version: 1`, carrying its basis so a compare
can check it: `pce` {host, org_id}, `scope` {kind, app, env,
identity_labels}, `basis` {window, window_days, filters}, `coverage`
{pce_flows, truncated, truncated_at, raw_observations, note}.

- `keys`: `[src, dst, service, decisions]` rows, sorted. The key is app pair
  x service (`tcp/443`); process, user, direction and time are not part of
  it. `decisions` is a fixed-order code string (`A` allowed, `P` potentially
  blocked, `B` blocked, `U` unknown): "AP" means seen both ways.
- `apps`: per app identity, `keys`, `peers_in`, `peers_out`,
  `external_destinations`, `external_sources`, `services`, `records`,
  `blocked_share`, `providers`, `in_scope`.
- `totals`: keys, apps, apps_in_scope, external destinations and sources,
  blocked share.
- `keys_omitted`: true when the key list did not fit the response budget;
  such a fingerprint is refused as a baseline.

Identity: the identity labels (`app (env)`), else FQDN, else attributed
provider, else `unlabelled:<hostname>` for a managed workload, else the
address, else an IP-list name. An IP-list name is context, not identity.

## Compare

`compare_fingerprints(current, baseline)`: refuse on a different
`fingerprint_version`, PCE, scope (kind, app, env), identity labels, query
filters, or a baseline without keys; warn on window lengths more than 10%
apart and on a truncated side. Then keys matched on identity: `new`,
`changed` (another decision set), `gone`, `same`; `drift` =
(new + changed + gone) / baseline keys; `by_app` with the same per app plus
`new_peers`, `gone_peers`, `new_external`; `new_providers`,
`gone_providers`. Lists are capped (200, then 50, then 0 to fit), counts
never are.

## Tool

`get-traffic-fingerprint` (reader, read-only). `scope`, `start_date` /
`end_date` / `lookback_days` (default: exactly 7 days ending now),
`baseline` xor `baseline_days` (1..365; the window before, same scope and
filters), `identity_labels`, `policy_decisions`, `max_results`. One Explorer
query per window with the scope's labels on both sides joined by `or`.

## Not done

No storage in the server: the client keeps fingerprints (illumio-tui's
snapshot directory is the natural home; this format is meant to become a
`traffic` section there). No scheduler, no alert threshold: drift is a
number the caller judges. No cross-estate benchmarking.
