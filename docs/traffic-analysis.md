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
| "Group by my own dimensions" | `get-traffic-flows-summary` + `group_by` | tuples on your keys |

The split matters: the summary reads the **whole window** and hands back tuples;
`get-traffic-flows` hands back rows and is therefore still capped.

---

## What changed, and why

A single constant used to answer two unrelated questions — how many rows to
**ask the PCE for**, and how many to **hand back**. Both were 500, so every
summary was computed from the first 500 rows the PCE happened to return.

Measured on demo100, a 30-day whole-estate window:

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
- {"from": "pos-web03-pci",  "to": "pos-proc03-pci",        ...}
+ {"from": "laptop (Users)", "to": "jump-infra (Production)", ...}
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
