---
title: Traffic analysis
layout: default
nav_order: 8
---

# Traffic Analysis

How the traffic tools read flows, what they aggregate, and how to get raw flows
when you actually want them.

---

## Which tool answers which question

| You want | Tool | Returns |
|---|---|---|
| "What talks to what?" | `get-traffic-flows-summary` | **aggregated tuples**, whole window |
| "Show me the actual flows" | `get-traffic-flows` | **raw flow rows**, capped at 500 |
| "Which process is going where?" | `discover-process-egress` | aggregated findings per process |
| "Which IPs talk to my workloads that the PCE does not know?" | `find-unknown-endpoints` | one profile per unknown address |
| "Group by my own dimensions" | `get-traffic-flows-summary` + `group_by` | tuples on your keys |

The split matters: the summary reads the **whole window** and hands back tuples;
`get-traffic-flows` hands back rows and is therefore still capped.

---

## What changed, and why

A single constant used to answer two unrelated questions — how many rows to
**ask the PCE for**, and how many to **hand back**. Both were 500, so every
summary was computed from the first 500 rows the PCE happened to return.

Measured on a mid-size demo estate, a 30-day whole-estate window:

| | Before | After |
|---|---|---|
| Rows analysed | 500 | **8,148** |
| Coverage of the window | **6%** | **100%** |
| `truncated` | `true` | `false` |

Not a representative 6% either — just whatever Explorer returned first, reported
with no denominator, so there was no way to tell.

The wide query is affordable because we aggregate: a tuple is **~89 bytes**
against **~2 KB** for a raw row. The window that is 16.5 MB raw is ~102 KB once
grouped.

---

## Completeness is now stated, never inferred

Three fields, and they mean different things:

| Field | Meaning |
|---|---|
| `totals.pce_flows` | rows **analysed** — the whole window |
| `totals.raw_observations` | what the PCE matched before its own aggregation |
| `section_totals` | how many tuples **exist** in each section |
| `truncated_sections` | which sections were trimmed **for display** |

**Read `section_totals`, not the array length**, to know how much exists. An
array is a display slice; its length never meant "this is all there is".

---

## `detail_level`: analysis vs display

```
detail_level: "standard"   (default) top 100 per section
detail_level: "full"       everything that fits the response limit
```

Both analyse **100% of the window**. `totals` and `section_totals` are identical
between them — only the number of displayed rows differs.

Measured on the same 30-day estate:

| Level | Response | ~Tokens | Shown |
|---|---|---|---|
| `standard` | 112 KB | ~28,000 | 100 per section |
| `full` | 348 KB | ~87,000 | all 1,399 blocked, all 351 app pairs |

Fitting inside the response limit is not the same as being worth sending. The
default trims the display; it does not trim the arithmetic.

---

## Label dimensions are not fixed to app/env

`app + env` is the Illumio convention for application identity, so it is the
default — but a PCE can define any dimensions it likes, and most real ones do.
One estate we tested against defines **15**, including `bu`, `type`, `os`,
`risk` and `compliance` alongside the familiar `role`, `app`, `env` and `loc`.

### Aggregate on a different axis

`identity_labels` changes what `app_to_app` treats as an endpoint's identity:

| `identity_labels` | Pairs | Top row |
|---|---|---|
| `["app","env"]` *(default)* | 351 | `vdi (Users) → jump-infra (Production)` |
| `["bu"]` | 63 | `commerce → shared-it` |
| `["compliance","env"]` | 79 | `PCI-DSS (PCI) → Production` |
| `["role","loc"]` | 497 | `processing (eu) → db (eu)` |

The first label is the subject, any others qualify it: `["app","env"]` renders
`ordering (Production)`, `["role","loc"]` renders `processing (ca)`.

Same machinery, different axis — the aggregation, budget and completeness
reporting are unchanged.

### `group_by` reaches every label too

Any label works as `source_<label>` or `destination_<label>`:

```json
{ "group_by": ["source_bu", "destination_bu", "port", "policy"] }
```

Matching is case-insensitive, so `source_businessunit` finds a `BusinessUnit`
label whatever case it was defined in. Unknown dimensions are **reported, not ignored** — silently grouping by
something else answers a different question.

### Discovering what a PCE has

Every summary response carries `available_dimensions`:

```json
"available_dimensions": {
  "named":  ["source_app", "dest_app", "port", "proto", "policy", ...],
  "labels": ["app", "bu", "compliance", "env", "loc",
             "os", "risk", "role", "type"],
  "usage":  "Any label works as source_<label> or destination_<label>, ..."
}
```

`labels` is what this PCE actually uses, not what it has defined — so it reflects
the estate in front of you.

### Sparse labels

Grouping on a label only some workloads carry is fine: endpoints lacking it show
as `unlabelled` rather than being dropped. Note that `app_to_app` excludes
self-pairs on whichever axis you choose, so `unlabelled → unlabelled` traffic is
not listed there — it is still counted in `totals`.

---

## "I just want the flows"

Use **`get-traffic-flows`**. It is unchanged: raw flow rows, capped at 500,
because raw rows go straight into the context window at ~2 KB each and 500 of
them is already ~1 MB.

```json
{ "start_date": "2026-08-18", "end_date": "2026-09-17",
  "include_sources": ["app=ordering"], "max_results": 500 }
```

To get *specific* raw flows rather than more of them, **narrow the query** —
label filters, ports and process filters are all pushed server-side, so a narrow
query returns the rows you want instead of the first 500 of everything.

Raising that cap is not on the roadmap. The point of the aggregate-first change
is that you rarely need raw rows; when you do, you need a *slice*, not a bigger
dump.

---

## Will this break what I already have?

**No keys were removed or renamed.** Two things did change meaning.

### 1. `app_to_app` values are apps now, not hostnames

```diff
- {"from": "web03-prod",     "to": "appsrv03-prod",          ...}
+ {"from": "vdi (Users)",    "to": "jump-infra (Production)", ...}
```

The section was documented as "the coarse app-to-app view" but grouped on a
label that prefers hostname, so it returned **1,394 host pairs where the app
view is 351**. Unmanaged and external endpoints appear as `external:<fqdn>`.

**Breaks:** anything string-matching hostnames in `app_to_app`.
**Fix:** match on `app (env)`, or use `group_by` with explicit dimensions if you
want workload-level output.

### 2. `truncated` means something different

- **Before:** "we only read 500 rows" — the answer was incomplete.
- **Now:** "the whole window was analysed; the display was trimmed."

**Breaks:** logic treating `truncated: true` as "re-run with a narrower window".
**Fix:** read `section_totals`, or pass `detail_level: "full"`.

### 3. Counts from earlier sessions are not comparable

They were computed from a fraction of the window. A connection count that
"went up" almost certainly did not — it is being measured properly now.

### Also worth knowing

- **Summaries are slower**: ~10s for 30 days on a mid-size estate, because they
  read the whole window. That is the query working, not a hang.
- **Responses are larger**: ~28k tokens at `standard`, up from ~8k.
- **`section_totals` is new** — additive, safe to ignore.

---

## What did *not* change

- `get-traffic-flows` — raw rows, still capped at 500.
- `group_by` and its dimensions, including `source_app` / `destination_app`,
  which still resolve to the raw label columns.
- The `by_process`, `external_destinations` and `blocked` section shapes.
- Every write tool.

---

## Timelines: flows per bucket from one query

```
get-traffic-timeline  { "lookback_days": 1, "bucket": "1h",
                        "policy_decisions": ["blocked"],
                        "include_destinations": ["app=shop", "env=prod"],
                        "spikes": true }
```

One Explorer query, bucketed client-side by `first_detected`. Every bucket in
the window is present, zeros included, aligned to the wall clock (`1h` on the
hour, `1d` at midnight UTC). `split_by: "policy_decision"` or `"direction"`
adds a per-bucket breakdown. `spikes: true` applies the rule shared with
illumio-tui -- a bucket at or above **3x the median of the non-zero buckets** --
and names the `worst` with its multiple.

**Read `effective_bucket` before quoting a spike.** Explorer aggregates older
flows per day, so a 1h timeline of last week is mostly day-wide rows whose
`first_detected` is 00:00. On one live estate that put 54 of 69 blocked rows in
the midnight bucket: a "27x spike" that was the aggregation. The response
reports `rows_spanning_buckets`, derives `effective_bucket` from the median row
span, and caveats `spikes` when the requested bucket is finer than the data.

---

## Unknown endpoints: addresses the PCE does not know

```
find-unknown-endpoints  { "lookback_days": 7, "direction": "both" }
find-unknown-endpoints  { "lookback_days": 7, "ip": "10.20.30.40" }
```

An endpoint is **unknown** when Explorer attached no workload to that side of
the flow **and** its IP is not an interface address of any inventoried
workload. Managed and unmanaged workloads both carry a workload object, so an
inventoried unmanaged workload is not unknown; the inventory join catches
workloads created after the flows were recorded and unmanaged workloads whose
hostname is empty. IP-list membership does not make an endpoint known: it is
reported under `ip_lists`, with the default `0.0.0.0/0` list dropped, because
a /8 in a list is not an inventory entry.

This is **not** `find-unmanaged-traffic`. That tool's test is "no `app`
label": it lists an unlabelled VEN and drops a labelled unmanaged workload.
`find-unknown-endpoints` counts unlabelled workloads in
`totals.unlabelled_workloads_seen` and does not profile them.

Three pulls: one Explorer query over the window (allowed, potentially blocked
and blocked), one workload inventory, one draft IP-list read. Each reports its
own truncation (`flows_truncated`, `inventory_truncated`,
`ip_lists_truncated`); `coverage_note` says what that does to the answer.

Per endpoint: `address_class` (private, public, or a noise class), `fqdn`,
`ip_lists`, `likely_provider` for public addresses, `neighbourhood` (the /24
or /64 it shares with N managed workloads: the strongest "this host should
have a VEN" signal), `as_source` and `as_destination` blocks with connections,
peer workloads, peer apps as `app (env)`, top-10 ports with an `admin` flag,
the policy mix and first/last seen, `peers_enforced`, and `profile`:

| Shape | Test |
|---|---|
| `scanner` | >= 10 peer x port pairs, median <= 3 connections per pair, >= 70% blocked or potentially blocked |
| `fan_in_server` | destination for >= 5 peer apps on <= 3 ports |
| `admin_reach` | source touching an admin port (22, 3389, 445, 1433, ...) on a workload |
| `high_volume` | >= 10x the median connections over unknown endpoints in that direction (needs >= 5) |
| `single_peer` | exactly one peer workload |

`profile_evidence` carries the numbers each test used. Link-local, multicast,
broadcast and loopback addresses are counted in `totals.noise_endpoints` and
listed only with `include_noise: true`.

With `ip` set the tool profiles one address: Explorer is filtered to it
server-side (one query per direction), the peer x port table is complete
instead of top-10, and a `timeline` is added using the same bucketing and
spike rule as `get-traffic-timeline` (1h buckets up to two days, else 1d).
An address that is in the inventory is answered as `known` without a query.
