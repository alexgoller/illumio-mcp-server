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
  "distinct_apps": 7,
  "external_destinations": 44,
  "distinct_destinations": 51,
  "first_seen": "2026-09-15T00:00:28Z",
  "last_seen":  "2026-10-01T23:59:35Z",
  "active_days": 15,
  "days_with_new_flows": 13,
  "window_days": 17,
  "activity_density": 0.88,
  "processes": ["chrome.exe", "Cursor.exe", "Google Chrome",
                "Microsoft Remote Desktop", "ssh", "mstsc.exe"] }
```

**Apps and external destinations are counted apart.** `distinct_apps` is reach
into the estate (app+env identities) and is what the wide-reach finding keys
on. `external_destinations` is everything else — FQDN, or the provider when
the address is attributable (`anthropic (internet)`, `aws-cloudfront
(internet)`), else the bare address with its IP list in parentheses. Counted
together, 40 internet addresses read as "reaches 43 destinations" and the
finding fired for 10 of 11 users.

**`activity_density`** is the ratio that carries the signal: 15 active days in a
17-day window is steady use; 2 in 30 is intermittent, and worth a different
question. A day is active if any flow attributed to the identity was live on
it -- Explorer aggregates a persistent connection into one row spanning
`first_detected..last_detected`, so a daemon connected for 26 days counts 26
days, not the one it started on.

That makes it an **upper bound**: one row of 2 connections spanning 30 days
also reads 30 of 30. `days_with_new_flows` — distinct days on which rows began
— is the matching lower bound. On an estate where every account is a steady
daily user, both sit near the window length and nothing is intermittent; that
is the data, not a defect.

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
| `note` | an interactive account reaches unusually many apps; intermittent activity |
| `expected` | a service account on many workloads — normal, but this is the blast radius if it is compromised |

**Nothing here is a verdict.** A backup agent on 200 workloads is correct; an
interactive account on 200 is a question. The output says what was observed and
why it was surfaced, and the phrase "lateral movement" is deliberately absent —
this data cannot distinguish that from a service doing its job.

---

## The window you asked for is not always the window you get

Explorer stores older flows as multi-day aggregates and returns any that
overlap the query window. A one-day query for 27 Sep came back with rows
starting 22 Sep and 1.67M connections — the aggregate's total, not the day's.
The response says so rather than labelling it 27 Sep:

```json
"window": { "start": "2026-09-27", "end": "2026-09-27",
            "data_span": { "earliest": "2026-09-21T00:00:00+00:00",
                           "latest":   "2026-09-27T23:59:59+00:00",
                           "extends_before_window": true,
                           "extends_after_window": false,
                           "note": "Rows extend outside the requested window ..." } }
```

`active_days` and `window_days` are clipped to the requested window;
`first_seen`/`last_seen` and `connections` are left as the data reports them.

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
