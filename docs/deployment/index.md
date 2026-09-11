---
title: Deployment
layout: default
nav_order: 7
has_children: true
---

# Deployment

Two supported topologies.

**stdio** — the server runs as a subprocess of the MCP client on one machine. No
authentication layer; whoever launches the process has full access. Right for a single
operator's laptop. See [Getting started](../getting-started).

**HTTP + OAuth** — one server for a team, behind your IdP, with role-based access,
per-user PCE credentials and an audit log. See [Central deployment](central).
