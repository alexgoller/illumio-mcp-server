---
title: Tool reference
layout: default
nav_order: 6
---

# Tool reference
{: .no_toc }

1. TOC
{:toc}

---

All 46 tools, grouped by area. Generated from the server's own registry by
`scripts/gen_tool_docs.py` -- do not edit by hand.

**Access** is the minimum role required. Roles are assigned from IdP group membership in
HTTP mode; in stdio mode every caller is `admin`.

| Badge | Meaning |
|---|---|
| *read* | Does not change the PCE |
| **write** | Mutates PCE objects (draft policy, labels, workloads, ...) |
| **confirm** | Mutating *and* gated behind a single-use confirmation token |


## Workloads

| Tool | Access | Type | Description |
|---|---|---|---|
| `create-workload` | operator | **write** | Create a Illumio Core unmanaged workload in the PCE |
| `delete-workload` | operator | **write** | Delete a workload from the PCE. Identify by href (preferred) or name. |
| `get-container-workload-profiles` | reader | *read* | Get Container Workload Profiles for a container cluster. These profiles control how Kubernetes pods are managed by Illumio — ma... |
| `get-kubernetes-workloads` | reader | *read* | Get Kubernetes Workloads (CLAS mode) from a container cluster. Shows Deployments, Services, and other K8s objects managed by Il... |
| `get-workload-enforcement-status` | reader | *read* | Get enforcement mode status across all workloads, grouped by application and environment. Shows counts per enforcement mode and... |
| `get-workloads` | reader | *read* | Get workloads from the PCE. Use detail_level to control breadth vs depth: 'compact' (default) for tabular overviews of thousand... |
| `update-container-workload-profile` | operator | **write** | Update a Container Workload Profile to manage Kubernetes pods in Illumio. Set managed=true and assign labels to start managing... |
| `update-workload` | operator | **write** | Update a workload in the PCE. Identify by href (preferred) or name. Provide only fields you want to change. |

## Labels

| Tool | Access | Type | Description |
|---|---|---|---|
| `create-label` | operator | **write** | Create a label of a specific type and the value in the PCE |
| `delete-label` | operator | **write** | Delete a label in the PCE |
| `get-labels` | reader | *read* | Get labels from the PCE with optional filtering |
| `update-label` | operator | **write** | Update an existing label in the PCE. Provide either: 1) href + new_value (optionally with key), or 2) key + value + new_value t... |

## IP lists

| Tool | Access | Type | Description |
|---|---|---|---|
| `create-iplist` | operator | **write** | Create a new IP List in the PCE |
| `delete-iplist` | operator | **write** | Delete an IP List from the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List. |
| `get-iplists` | reader | *read* | Get IP lists from the PCE with optional filtering |
| `update-iplist` | operator | **write** | Update an existing IP List in the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List. |

## Services

| Tool | Access | Type | Description |
|---|---|---|---|
| `create-service` | operator | **write** | Create a new service definition in the PCE |
| `delete-service` | operator | **write** | Delete a service from the PCE. Identify by href (preferred) or name. |
| `get-services` | reader | *read* | Get services from the PCE with optional filtering |
| `identify-infrastructure-services` | reader | *read* | Analyze traffic flows to identify infrastructure services in your environment.
Builds an app-to-app communication graph and com... |
| `update-service` | operator | **write** | Update an existing service in the PCE. Identify by href (preferred) or name. |

## Rulesets and rules

| Tool | Access | Type | Description |
|---|---|---|---|
| `create-deny-rule` | operator | **write** | Create a deny rule in an existing ruleset. Deny rules block specific traffic (processed after allow rules). Override deny rules... |
| `create-ruleset` | operator | **write** | Create a ruleset in the PCE with support for ring-fencing patterns |
| `delete-deny-rule` | operator | **write** | Delete a deny rule from a ruleset by its href |
| `delete-ruleset` | operator | **write** | Delete a ruleset from the PCE by its href |
| `get-rulesets` | reader | *read* | Get rulesets from the PCE with optional filtering |
| `update-deny-rule` | operator | **write** | Update an existing deny rule in a ruleset. Identify the rule by its href. |
| `update-ruleset` | operator | **write** | Update an existing ruleset in the PCE. Provide either 'href' or 'name' (but not both) to identify the ruleset. |

## Traffic analysis

| Tool | Access | Type | Description |
|---|---|---|---|
| `find-unmanaged-traffic` | reader | *read* | Find traffic involving unmanaged (unlabeled) workloads or IP addresses. These are sources or destinations without app/env label... |
| `get-traffic-flows` | reader | *read* | Get traffic flows from the PCE with comprehensive filtering options |
| `get-traffic-flows-summary` | reader | *read* | Get traffic flows from the PCE in a summarized text format, this is a text format that is not a dataframe, it also is not json,... |

## Ringfencing and threat analysis

| Tool | Access | Type | Description |
|---|---|---|---|
| `create-ringfence` | operator | **write** | Create a ringfencing policy for an application. This analyzes traffic flows to discover
which other apps communicate with this... |
| `detect-lateral-movement-paths` | reader | *read* | Analyze traffic patterns to detect potential lateral movement paths — chains of connections that could allow an attacker to piv... |
| `ringfence-batch` | admin | **confirm** | Create ringfence policies for multiple applications at once. Optionally auto-discovers infrastructure services and ringfences t... |

## Policy and compliance

| Tool | Access | Type | Description |
|---|---|---|---|
| `compare-draft-active` | reader | *read* | Compare draft vs active policy to see what would change on provisioning. Shows new, modified, and deleted rulesets, rules, IP l... |
| `compliance-check` | reader | *read* | Check policy compliance against common frameworks (PCI-DSS, NIST, CIS). Identifies workloads in specific compliance scopes and... |
| `enforcement-readiness` | reader | *read* | Assess whether an application is ready for enforcement by analyzing its traffic flows, existing policy coverage, and identifyin... |
| `get-policy-coverage-report` | reader | *read* | Generate a policy coverage report for an app, showing what traffic is covered by existing rules vs what would be blocked. Helps... |
| `provision-policy` | admin | **confirm** | Provision pending draft policy changes in the PCE. This moves draft rulesets, rules, IP lists, services, and label groups from... |

## Containers

| Tool | Access | Type | Description |
|---|---|---|---|
| `get-container-clusters` | reader | *read* | Get container clusters (Kubernetes/OpenShift) registered in the PCE. Shows cluster name, CLAS mode, online status, kubelink ver... |

## PCE and credentials

| Tool | Access | Type | Description |
|---|---|---|---|
| `check-pce-connection` | reader | *read* | Are my credentials and the connection to the PCE working? |
| `check-pce-credentials-status` | reader | *read* | Check whether PCE credentials are registered for the current user without revealing the secret values. |
| `delete-pce-credentials` | reader | **write** | Remove the current user's stored PCE credentials. Idempotent — safe to call even if no credentials are stored. |
| `get-events` | reader | *read* | Get events from the PCE with optional filtering |
| `get-pairing-profiles` | reader | *read* | Get pairing profiles from the PCE. Pairing profiles define the initial enforcement mode and labels for VENs when they pair with... |
| `register-pce-credentials` | reader | **write** | Register (or overwrite) PCE credentials for the current authenticated user. After registering, all PCE tools become available i... |

## Confirmation-gated tools

Two tools require a second, explicit step before they run:

- `provision-policy` -- commits draft policy, changing live enforcement
- `ringfence-batch` -- writes ringfence policy for many applications at once

In HTTP mode the caller must obtain a single-use token from `POST /confirm` and present
it in `_meta.confirm_token`. The token is bound to the caller, the tool name, and a hash
of the exact arguments, so approval for one change cannot be replayed for another. See
[Security model](security-model#the-confirmation-gate).

In stdio mode the gate is not enforced -- there is no authenticated identity to bind a
token to.

## Tools that work without PCE credentials

`register-pce-credentials`, `delete-pce-credentials` and `check-pce-credentials-status`
are credential self-service and run before any PCE key exists. Everything else requires
working credentials.
