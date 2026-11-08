---
title: Cloud Platform (optional)
layout: default
nav_exclude: true
search_exclude: true
---

# Illumio Cloud Platform integration

Optional, configuration-enabled, and deliberately not on the front page. When
the four variables below are set, six `cloud-*` tools exist; when any is
missing, the server behaves as if the feature had never been written -- they
are not advertised, calling one is an ordinary unknown tool, and the public
tool reference does not list them.

| Var | Meaning |
|---|---|
| `CLOUD_API_HOST` | e.g. `https://cloud.illum.io` |
| `CLOUD_API_KEY` / `CLOUD_API_SECRET` | an Illumio Cloud API key pair |
| `CLOUD_TENANT_ID` | the tenant the key belongs to |
| `CLOUD_TLS_VERIFY` | optional, `false` for a private endpoint with its own CA |
| `MCP_HIDE_FEATURES` | optional, `cloud` hides the feature even when configured |

Both clients authenticate with Basic auth plus `X-Tenant-Id` (the `x-api-key`
header pair the original branch used answers 401 on cloud.illum.io, measured
2026-11-08) and carry the same bounded retry and timeout policy as the PCE
client.

| Tool | Access | Does |
|---|---|---|
| `cloud-get-resources` | read | inventory, filtered and paginated; `compact` flattens labels to columns, `full` returns the resource JSON |
| `cloud-assign-labels` / `cloud-remove-labels` | write (operator, admin) | label assignments by `csp_id`; the response lists `failed_resources` |
| `cloud-get-traffic-queries` | read | unified-traffic (FQS) async query statuses |
| `cloud-create-traffic-query` | write | create an async FQS query |
| `cloud-get-traffic-flows` | read | download a completed query, grouped by endpoint pair, port, protocol and decision |

Verified 2026-11-08 on a live tenant: inventory lists 4,532 resources with
labels as columns. The FQS endpoints authenticated but answered
500 *Failed to read CSI value* on that tenant; the tools report that as the
upstream error it is.
