---
title: Identity graph
layout: default
nav_order: 9
---

# Identity Graph

Illumio records a `user_name` on each flow — the account the communicating
process ran as. That turns flow data into an identity question, which workload
labels cannot answer: **what can this account reach, from how many places, and
over what period.**

```
build-identity-graph  { "lookback_days": 30 }
```

---

## Identity resolution comes first

The same person arrives under more than one spelling. On one live estate,
`CRYSTAL\agarcia` and `agarcia` turned out to be **one human on two devices** —
a domain-joined Windows endpoint and a Mac with a local account. Unresolved,
every interactive user was counted twice: 26 "identities" that were 13 people.

So the domain qualifier is stripped for identity and **kept as an attribute**:

```json
{ "identity": "agarcia",
  "seen_as": ["CRYSTAL\\agarcia", "agarcia"],
  "observed_on_workloads": 2 }
```

`DOMAIN\user` and `user@realm` both resolve. The `identity` filter accepts
either spelling.

---

## Two classes, read differently

| Class | Example | Host spread means |
|---|---|---|
| `service` | `root`, `NT AUTHORITY\SYSTEM`, `mysql`, `tomcat` | **normal** — that is what a daemon does |
| `interactive` | `agarcia`, `bjones` | **notable** — one person, or a shared credential |

Classification is by construction, not behaviour — well-known principals
(`NT AUTHORITY\*`), conventional daemon names, machine accounts (`HOST$`), and
`svc-`/`sa_` naming. Every identity reports `classified_because`, so you can
disagree with the call.

---

## What you get per identity

```json
{ "identity": "agarcia",
  "class": "interactive",
  "observed_on_workloads": 2,
  "distinct_destinations": 8,
  "first_seen": "2026-09-15T00:00:28Z",
  "last_seen":  "2026-10-01T23:59:35Z",
  "active_days": 15,
  "window_days": 17,
  "activity_density": 0.88,
  "processes": ["chrome.exe", "Cursor.exe", "Google Chrome",
                "Microsoft Remote Desktop", "ssh", "mstsc.exe"] }
```

**`activity_density`** is the ratio that carries the signal: 15 active days in a
17-day window is steady use; 2 in 30 is intermittent, and worth a different
question.

The process list often tells the story on its own — `chrome.exe` and `mstsc.exe`
alongside `Google Chrome` and `Microsoft Remote Desktop` is one person working
from a Windows and a Mac machine.

---

## Findings are ranked by how unexpected they are

Thresholds alone put `root on 235 workloads` at the top — a daemon doing its
job — and bury the finding that needs a person. So each signal carries an
interest level:

| Interest | Surfaced when |
|---|---|
| `review` | an interactive account acts from several workloads, or any of its flows are already blocked |
| `note` | an interactive account reaches unusually many destinations; intermittent activity |
| `expected` | a service account on many workloads — normal, but this is the blast radius if it is compromised |

**Nothing here is a verdict.** A backup agent on 200 workloads is correct; an
interactive account on 200 is a question. The output says what was observed and
why it was surfaced, and the phrase "lateral movement" is deliberately absent —
this data cannot distinguish that from a service doing its job.

---

## Coverage is partial, and says so

The PCE records an account only when the VEN could attribute the flow to one. On
one estate that was **7,737 of 14,133 rows**, so `totals` reports both:

```json
"totals": { "flow_rows": 14133,
            "rows_with_identity": 7737,
            "rows_without_identity": 6396 }
```

A low ratio is a **visibility gap, not an absence of activity**. Flows without an
account are counted, never silently dropped.

---

## Arguments

| Argument | Effect |
|---|---|
| `lookback_days` / `start_date` / `end_date` | the window (default 30 days) |
| `identity` | restrict to accounts, either spelling |
| `include_service_accounts` | default `true`; `false` to look only at people |
| `include_edges` | identity → workload → destination edges, capped at 400 |
| `include_sources` / `include_destinations` | label filters, pushed server-side |
| `policy_decisions` | `allowed`, `blocked`, `potentially_blocked` |

The query reads the whole window; only the display is bounded.
