---
title: Workflows & prompts
layout: default
nav_order: 4
---

# Workflows and prompts
{: .no_toc }

1. TOC
{:toc}

---

The server ships three **MCP prompts** — guided, multi-step workflows that sequence the
underlying tools for a task, so you don't have to drive 46 tools by hand. In Claude
Desktop they appear in the prompt picker (the `+` menu); other clients expose them via
`prompts/list`.

Every application is addressed by **app + environment**, which together form its identity
in Illumio.

## `analyze-application-traffic`

Start here. Read-only, and the prerequisite for any sensible policy work.

| Argument | Required | Meaning |
|---|---|---|
| `application_name` | yes | e.g. `payments` |
| `application_environment` | yes | e.g. `production` |

Walks the traffic for one application: who talks to it, what it talks to, on which
services, and which flows existing policy already allows. Produces the picture you need
before writing a single rule.

```
Analyze traffic for the payments app in production
```

## `ringfence-application`

Deploys rulesets that constrain an application's inbound and outbound traffic, based on
what its traffic actually shows.

| Argument | Required | Meaning |
|---|---|---|
| `application_name` | yes | Application to ringfence |
| `application_environment` | yes | Its environment |

A ringfence is coarse-grained segmentation: an intra-scope allow rule so the app's own
tiers can talk, plus extra-scope allow rules for the remote apps it legitimately needs.
Rules are written as **draft** policy — nothing changes until provisioned.

{: .note }
> A *selective* ringfence additionally writes a deny rule. In selective enforcement the
> default is allow-all, so the deny rule is what actually enforces the boundary, while
> allow rules for known apps are processed first. See
> [rule processing order](resources#concepts).

```
Ringfence the payments app in production
```

## `emergency-isolate-application`

{: .warning }
> Blocks **all** traffic to and from the application immediately, overriding existing
> allow rules. For security incidents only.

| Argument | Required | Meaning |
|---|---|---|
| `application_name` | yes | Application to isolate |
| `application_environment` | yes | Its environment |

Uses **override deny** rules, which are evaluated before every allow rule — the one
mechanism that beats existing policy. This is deliberately not part of normal
ringfencing; it is the break-glass path for a compromised workload.

```
Emergency isolate the compromised-app in production
```

## Building your own

The prompts are conveniences, not the only path. Anything they do, you can ask for
directly, and the model will choose tools itself. A productive pattern is to chain the
read-only analysis tools and stop before the write:

```
1. get-traffic-flows-summary        what is actually happening
2. identify-infrastructure-services what is shared and should be policied first
3. get-policy-coverage-report       what is already covered
4. enforcement-readiness            what would break
```

If you use Claude Code, you can wrap that sequence in a project skill or slash command so
the whole review runs on one invocation. The server itself has no notion of skills — it
exposes tools, prompts and resources, and any skill layer lives in your client.

## Grounding the model

The server also exposes 20 **resources** — an embedded knowledge base covering rule
processing order, enforcement modes, compliance frameworks and segmentation methodology.
Clients can attach these to the conversation so the model reasons with Illumio's actual
semantics rather than generic firewall intuition.

[Browse the knowledge base →](resources)
