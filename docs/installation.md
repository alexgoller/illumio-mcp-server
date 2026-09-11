---
title: Installation
layout: default
nav_order: 2
---

# Installation
{: .no_toc }

1. TOC
{:toc}

---

## Prerequisites

| | |
|---|---|
| Python | 3.12 or 3.13 (`>=3.12,<3.14` — 3.14 is excluded because `pydantic-core` fails to build) |
| Package manager | [`uv`](https://docs.astral.sh/uv/) recommended |
| PCE access | Hostname, port, org ID, and an API key/secret pair |
| MCP client | Claude Desktop, Claude Code, or any MCP-capable client |

Generate the PCE API key in the PCE UI under **Access → API Keys**. Give it the minimum
role the tools you intend to use require — read-only if you only plan to query.

## With uv (recommended)

```bash
git clone https://github.com/alexgoller/illumio-mcp-server.git
cd illumio-mcp-server
uv sync
```

`uv sync` resolves from `uv.lock`, so you get the exact dependency set the project tests
against — including the security floors on transitive packages.

## With pip

```bash
git clone https://github.com/alexgoller/illumio-mcp-server.git
cd illumio-mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

{: .note }
> There is no `requirements.txt`. Dependencies live in `pyproject.toml`; a stale
> requirements file was removed because it pinned versions no build ever used.

## With Docker

```bash
docker build -t illumio-mcp .
docker run --rm -i \
  -e PCE_HOST=pce.example.com \
  -e PCE_PORT=8443 \
  -e PCE_ORG_ID=1 \
  -e API_KEY=api_xxxxx \
  -e API_SECRET=xxxxx \
  -e DOCKER_CONTAINER=true \
  illumio-mcp
```

`DOCKER_CONTAINER=true` routes the diagnostic log to `/var/log/illumio-mcp/` instead of
the working directory. The image runs as a non-root user (`uid 1000`).

## Verify

```bash
.venv/bin/python -m illumio_mcp   # should start and wait on stdin
```

It exits cleanly when stdin closes. Nothing is printed on success — the server writes
only MCP protocol messages to stdout, and diagnostics go to the log file.

To confirm PCE connectivity, ask your MCP client to run `check-pce-connection`, or see
[Troubleshooting](operations/troubleshooting).

## Next

- [Getting started](getting-started) — wire it into Claude Desktop and run your first query
- [Central deployment](deployment/central) — run one server for a whole team
