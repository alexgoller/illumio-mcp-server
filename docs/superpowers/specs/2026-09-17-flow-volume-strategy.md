# Beyond the 500-flow cap: aggregate-first traffic analysis

**Status:** Proposed. Measured against demo100 (org 5636114) on 2026-09-17.
**Author:** Alex Goller (with Claude)

---

## 1. The measurement that decides this

A 30-day, whole-estate query on demo100, requested uncapped:

| Stage | Count | Size |
|---|---|---|
| Raw observations (`matches_count`) | 19,860 | — |
| Rows Explorer actually returns | 7,967 | **16.5 MB** |
| Aggregated to app+env × app+env × port/proto × decision | **1,151** | **102 KB** |

**162× smaller, and it fits the 800 KB response budget with room to spare.**

Two facts follow, and they reframe the whole problem:

**Explorer already aggregates.** 19,860 observations arrive as 7,967 rows. What
the PCE hands us are *already* metadata tuples, not packets. We have never been
anywhere near "individual flows".

**The cap is a response-size constraint wearing a query-size costume.** A raw
Explorer row serialises to ~2.07 KB, so only ~400 fit in 800 KB — which is
exactly why the cap is 500. An aggregated tuple is **89 bytes**, so roughly
**9,000** fit in the same budget.

We are not limited to 500 flows. We are limited to 500 *rows of a shape we
should not be returning*.

### How far things collapse, by granularity

| Aggregation | Tuples | Reduction |
|---|---|---|
| port/proto only | 59 | 135× |
| app × app | 163 | 49× |
| app+env × app+env | 184 | 43× |
| app × app × port/proto | 701 | 11× |
| app+env × app+env × port/proto | 764 | 10× |
| + policy_decision | 1,151 | 7× |
| workload × workload × port/proto | 1,677 | 4.8× |
| src IP × dst IP × port/proto | 4,110 | 1.9× |

The right-hand end of that table is where the cap bites, and it is also the end
nobody asks questions about. Segmentation questions live in the top half.

---

## 2. The principle

> **Cap the answer, not the question.**

Today one constant, `MCP_BUG_MAX_RESULTS = 500`, is used for both, which is why
raising it for ringfence discovery (500 → 100,000) was safe and necessary: that
code path already aggregated before responding. Generalise that.

Two separate budgets:

- **Query budget** — how much we ask the PCE for. Should be effectively
  unbounded; the cost is wall-clock and memory in *our* process.
- **Response budget** — how much reaches the model. Stays at 800 KB, and gets
  spent on tuples rather than rows.

---

## 3. Architecture

### Tier 0 — Pull wide

Ask the Explorer async API for everything in the window. It already handles
200,000 without complaint. Keep `fetch_flows_raw`'s `matches_count` capture so
we always know the true denominator.

### Tier 1 — Aggregate before anything else

The machinery exists: `GROUP_DIMENSIONS`, `group_flows()`, `resolve_group_by()`.
The change is that aggregation becomes the **default path**, not a post-hoc
option applied to an already-truncated set. Default grouping:

```
src app+env, dst app+env, port, proto, policy_decision
  -> connections, flow_count, first_seen, last_seen, distinct_workloads
```

Process and FQDN stay available as extra dimensions, not defaults — adding
process takes 1,151 tuples to ~3,500 and is only wanted when the question is
about processes.

### Tier 2 — Spend the response budget by relevance

Fill 800 KB with the tuples that answer the question, ranked deliberately:

- **volume** (connections) for "what talks to what"
- **policy risk** (blocked / potentially_blocked first) for enforcement readiness
- **novelty** (first_seen inside the window) for drift

Always report the denominator: `1,151 of 1,151 tuples (complete)` or
`returned 900 of 4,200 tuples, ranked by connections`. Completeness must be a
fact in the payload, never an inference from a row count.

### Tier 3 — Escalation paths, in cost order

1. **Narrow, don't paginate.** A second call with a label or port filter pushed
   *server-side* is cheaper and more precise than fetching page 2.
2. **Drill-down on a tuple.** `explain-tuple(src, dst, port)` returns the raw
   rows behind one aggregate — the only place raw rows are ever appropriate,
   and naturally bounded.
3. **Stable cursor over the aggregate.** Sort is deterministic, so
   `offset`/`limit` over *tuples* is coherent in a way paging over flows is not.
4. **`ResourceLink`.** mcp 1.29.1 supports it. Large results are written once
   and returned as a link; the client fetches only if the user asks. Keeps a
   16 MB dataset reachable without putting it in the context window.

### Tier 4 — `structuredContent`

`CallToolResult.structuredContent` (mcp 1.29.1) carries the aggregate as typed
JSON alongside a short human summary, instead of a JSON string inside prose.
Cheaper to parse, cheaper in tokens.

---

## 4. Where the MCP 2026-07-28 migration becomes relevant

The deferred migration design (`2026-07-30-mcp-2026-07-28-migration-design.md`)
listed revival triggers. This is one.

An uncapped 90-day query on a large estate takes minutes. Today that is a silent
stall indistinguishable from a hang — the same class of problem as the approval
pause we documented in 0.2.0. First-class **tasks with progress** turn it into
"fetched 40,000 of ~120,000 observations". That is the concrete use case the
design doc said to wait for.

---

## 5. What should stay capped, honestly

The user's instinct is right: limits and aggregation are features, not
compromises.

- **Raw-row responses stay capped.** Drill-down is bounded by construction.
- **Process/FQDN dimensions stay opt-in.** They multiply cardinality ~3× and are
  irrelevant to most questions.
- **Unbounded `group_by` combinations should be refused**, not truncated. Asking
  for src IP × dst IP × port × process over 90 days is a request for a dataset,
  not an answer; the tool should say so and suggest a narrower question.
- **The response budget itself stays.** 800 KB of tuples is already more than a
  model reasons well over. The binding constraint becomes *usefulness*, not
  transport — which is the right place for it to sit.

---

## 6. Risks

- **Memory.** 16.5 MB of JSON for demo100; a large estate could be 10–20×. Parse
  into a DataFrame and discard the JSON, or aggregate incrementally.
- **PCE load.** Uncapped async queries are heavier. They are the API's intended
  use, but a per-query ceiling (say 500k observations) with a clear error beats
  an unbounded request.
- **Wall-clock.** See §4. Needs progress reporting before it is pleasant.
- **Explorer's own ceiling** is not yet known — 200,000 was never binding on
  demo100. Must be measured on a large estate before promising "uncapped".

---

## 7. Sequencing

1. Split the constant: `MCP_QUERY_MAX_RESULTS` (high) vs
   `MCP_RESPONSE_MAX_BYTES` (800 KB). Mechanical, removes the conflation.
2. Make `get-traffic-flows-summary` aggregate-first with the default grouping,
   reporting the true denominator.
3. Add `explain-tuple` drill-down; raw rows only there.
4. Rank-and-fill the response budget; refuse pathological `group_by`.
5. `structuredContent` for the aggregate.
6. `ResourceLink` for full datasets.
7. Revisit the 2026-07-28 migration for task progress.

Steps 1–2 alone convert "500 flows" into "the whole estate, 30 days, complete"
for every question that matters.
