---
title: Process-qualified rules
layout: default
nav_order: 7
---

# Process-Qualified Rules

How to write "only this binary may reach that application" — the pattern behind
the Shadow AI demo. Every API behaviour on this page was measured against a live
PCE, because several of them differ from what the object model suggests.

---

## The shape of it

Three objects, in this order:

1. **A service qualified by process** — `windows_egress_services`.
2. **An allow rule** carrying the port in `ingress_services` and the process
   service in `egress_services`.
3. **A broad deny below it** — `{"service": "All Services"}`.

```json
// 1. the process qualifier
{ "name": "S-VDI-chrome-egress",
  "windows_egress_services": [
    { "process_name": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" }
  ] }

// 2. the allow: port on the provider side, process on the consumer side
{ "providers": ["app=payment"], "consumers": ["app=vdi"],
  "ingress_services": [{ "port": 443, "proto": "tcp" }],
  "egress_services": [{ "service": "S-VDI-chrome-egress" }],
  "unscoped_consumers": true }

// 3. the deny, evaluated after allow rules
{ "providers": ["app=payment"], "consumers": ["ams"],
  "ingress_services": [{ "service": "All Services" }] }
```

---

## Three things that are not obvious

**A service carries an OS type, and the qualifier lists are mutually exclusive.**
`service_ports`, `windows_services` and `windows_egress_services` cannot be
combined. Sending two, the PCE keeps one, nulls the other, and still answers
`201` — so "chrome.exe on 443" is *not* one service object. Editing one into
another answers `cannot change OS type of service`. The tools refuse the
combination up front rather than letting a half-discarded object look like
success.

**`windows_egress_services` takes `process_name` / `service_name` only.** A port
there is rejected outright. The port lives on the rule, which is why the pattern
above splits them across `ingress_services` and `egress_services`.

**A Windows egress service cannot go in `ingress_services`.** The PCE answers
`ingress_service_cannot_be_windows_egress_service` without saying where it
belongs. It belongs in `egress_services`: that field qualifies *which process on
the consumer* may use the rule, while `ingress_services` stays the provider-side
port. The two together express "this binary, to that port".

---

## Process path matching

`process_name` is passed through exactly as given — no case folding, no slash
rewriting, because the VEN matches it literally.

| Value | Matches |
|---|---|
| `C:\Program Files\Google\Chrome\Application\chrome.exe` | that binary at that path |
| `chrome.exe` | any binary of that name, in any directory |

The bare form is wider than it looks: anything a user renames to `chrome.exe`
matches it.

---

## Windows VEN required

`windows_egress_services` is evaluated on the **consumer** and needs a Windows
VEN there. A Linux consumer ignores the process qualifier and matches on the
port alone — so the rule is silently *wider* than it reads: "chrome.exe on 443"
becomes "any process on 443" for those workloads.

The tools check the consumers in scope and return a `policy_widening_warning`
naming the non-Windows workloads when this applies.

---

## Deny rules cannot be process-qualified

The PCE evaluates a deny without process context, so a process-qualified service
in a deny would apply to its ports alone — broader than intended. The tools
reject it with that explanation.

The supported shape is always **a qualified allow above a broad deny**: allow
rules are evaluated first, so the narrow allow wins and everything else falls
through to the deny.

---

## Referring to services

Anywhere a rule takes services, each entry is one of:

| Form | Use |
|---|---|
| `{"port": 443, "proto": "tcp"}` | inline port |
| `{"href": "/orgs/1/sec_policy/draft/services/42"}` | a specific object |
| `{"service": "All Services"}` | by exact name |

Mixing those keys in one entry is an error — it used to be resolved by silently
dropping the href, which stored `0/tcp` and reported success.

Name resolution is exact. The PCE matches `?name=` as a substring, so `S-HTTP`
also returns `S-HTTPS` and `S-HTTPS-UDP`; the tools filter to the exact match and
report ambiguity rather than guessing.
