---
title: Knowledge base
layout: default
nav_order: 5
---

# Embedded knowledge base
{: .no_toc }

1. TOC
{:toc}

---

The server exposes 20 MCP **resources** under the `illumio://` scheme. These are curated
reference documents the model can pull into context, so its reasoning reflects how
Illumio actually behaves rather than generic firewall assumptions.

Most clients let you attach resources explicitly; some fetch them on demand. In Claude
Desktop they appear in the attachment menu.

## Concepts

The semantics that most often trip people up.

| URI | Covers |
|---|---|
| `illumio://concepts/rule-processing` | The order rules are evaluated in — essential, and counter-intuitive |
| `illumio://concepts/enforcement-modes` | Selective vs full enforcement, and why the default action differs |
| `illumio://concepts/segmentation` | Core segmentation model |
| `illumio://concepts/draft-active-policy` | Why writing a rule changes nothing until you provision |
| `illumio://concepts/workloads` | Managed, unmanaged and container workloads |

{: .note }
> **Rule processing order**, condensed: essential rules → override deny → allow →
> deny → default action. The default depends on enforcement mode: in *selective* it is
> allow-all, so only deny rules bite; in *full* it is deny-all, so only explicit allows
> pass. This single fact determines whether a ringfence needs a deny rule to work.

## Architecture

| URI | Covers |
|---|---|
| `illumio://architecture/pce-ven` | How the PCE and VEN relate |
| `illumio://architecture/labels` | The label dimensions and why app+env is an identity |

## Methodology

How to approach a segmentation programme, not just the API.

| URI | Covers |
|---|---|
| `illumio://methodology/first-principles` | Where to start |
| `illumio://methodology/core-services` | Policy infrastructure services first, and why |
| `illumio://methodology/ringfencing-patterns` | Standard vs selective ringfencing |
| `illumio://methodology/crown-jewels` | Protecting the highest-value assets first |

## Compliance

Framework mappings for segmentation controls.

| URI | Framework |
|---|---|
| `illumio://compliance/pci-dss` | PCI-DSS |
| `illumio://compliance/hipaa` | HIPAA |
| `illumio://compliance/nist-800-53` | NIST 800-53 |
| `illumio://compliance/iso-27001` | ISO 27001 |
| `illumio://compliance/dora` | DORA |
| `illumio://compliance/swift-csp` | SWIFT CSP |
| `illumio://compliance/cis-controls` | CIS Controls |
| `illumio://compliance/segmentation-methodology` | Segmentation as a compliance control |

The `compliance-check` tool evaluates live policy against several of these.

## Operations

| URI | Covers |
|---|---|
| `illumio://operations/logging-monitoring` | Logging and monitoring guidance |
