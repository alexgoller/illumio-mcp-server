---
title: Home
layout: default
nav_order: 1
description: "Manage Illumio PCE segmentation from any MCP client."
permalink: /
---

# Illumio MCP Server
{: .fs-9 }

Drive Illumio PCE segmentation from Claude, or any MCP client — workloads, labels,
rulesets, traffic analysis, ringfencing and policy provisioning.
{: .fs-6 .fw-300 }

[Get started](getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/alexgoller/illumio-mcp-server){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What it is

An [MCP](https://modelcontextprotocol.io) server that exposes the Illumio Policy Compute
Engine as tools an AI assistant can call. Ask for "the traffic between the POS app and its
database last week" or "ringfence the payments app in production", and the model works
through the PCE API on your behalf.

| | |
|---|---|
| **46 tools** | Full CRUD on workloads, labels, IP lists, services, rulesets and deny rules, plus traffic analysis, ringfencing, compliance checks and policy provisioning. [Reference →](tools) |
| **3 guided workflows** | Multi-step prompts for ringfencing, traffic analysis and emergency isolation. [Workflows →](workflows) |
| **20 knowledge resources** | An embedded segmentation knowledge base — rule processing order, enforcement modes, PCI-DSS/HIPAA/DORA/NIST mappings, ringfencing patterns. [Resources →](resources) |
| **2 transports** | `stdio` for a laptop, or HTTP with OAuth for a team. [Deployment →](deployment/central) |

## Two ways to run it

**On your laptop (stdio).** Each user installs the server locally and supplies their own
PCE key. Fastest path, nothing to operate. [Getting started →](getting-started)

**Centrally (HTTP + OAuth).** One server for the whole team. Users authenticate through
your IdP, roles come from group membership, and each person's PCE credentials are stored
encrypted so the PCE's own audit log attributes actions to the human who took them.
[Central deployment →](deployment/central)

{: .warning }
> This server can change firewall policy. `provision-policy` and `ringfence-batch` mutate
> production segmentation. Read [Security](security-model) before pointing it at a
> production PCE, and start against a test PCE.

## Quick taste

```
You: Which applications talk to the payments app in production?
     → get-traffic-flows-summary

You: Show me what would change if I provisioned right now.
     → compare-draft-active

You: Is the payments app ready for enforcement?
     → enforcement-readiness
```

---

Community project. Not an official Illumio product. Licensed under GPL-3.0.
