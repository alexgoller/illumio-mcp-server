#!/usr/bin/env python3
"""Regenerate docs/tools.md from the live tool registry.

The published tool reference is derived, never hand-edited -- a hand-maintained
list is one more place to forget when a tool is added, which is exactly how the
test suite's tool-list assertion went stale.

    .venv/bin/python scripts/gen_tool_docs.py          # write docs/tools.md
    .venv/bin/python scripts/gen_tool_docs.py --check  # fail if out of date
"""
from __future__ import annotations

import asyncio
import pathlib
import sys

import mcp.types as t

import illumio_mcp.server as S
from illumio_mcp.tools import TOOL_REGISTRY

OUT = pathlib.Path(__file__).resolve().parents[1] / "docs" / "tools.md"

GROUPS = [
    ("Workloads", ["workload"]),
    ("Labels", ["label"]),
    ("IP lists", ["iplist"]),
    ("Services", ["service"]),
    ("Rulesets and rules", ["ruleset", "rule"]),
    ("Traffic analysis", ["traffic", "unmanaged"]),
    ("Ringfencing and threat analysis", ["ringfence", "infrastructure", "lateral"]),
    ("Policy and compliance", ["policy", "enforcement", "compliance", "draft"]),
    ("Containers", ["container", "kubernetes"]),
    ("PCE and credentials", ["pce", "events", "pairing"]),
]

HEADER = """---
title: Tool reference
layout: default
nav_order: 6
---

# Tool reference
{{: .no_toc }}

1. TOC
{{:toc}}

---

All {n} tools, grouped by area. Generated from the server's own registry by
`scripts/gen_tool_docs.py` -- do not edit by hand.

**Access** is the minimum role required. Roles are assigned from IdP group membership in
HTTP mode; in stdio mode every caller is `admin`.

| Badge | Meaning |
|---|---|
| *read* | Does not change the PCE |
| **write** | Mutates PCE objects (draft policy, labels, workloads, ...) |
| **confirm** | Mutating *and* gated behind a single-use confirmation token |
"""

FOOTER = """
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
"""


def _access(spec) -> str:
    return {1: "admin", 2: "operator"}.get(len(spec.roles), "reader")


def render() -> str:
    handler = S.server.request_handlers[t.ListToolsRequest]
    listed = asyncio.run(handler(t.ListToolsRequest(method="tools/list"))).root.tools
    tools = {x.name: x for x in listed}

    out = [HEADER.format(n=len(TOOL_REGISTRY))]
    seen: set[str] = set()
    for title, keys in GROUPS:
        names = [n for n in sorted(tools) if any(k in n for k in keys) and n not in seen]
        seen |= set(names)
        if not names:
            continue
        out.append(f"\n## {title}\n")
        out.append("| Tool | Access | Type | Description |")
        out.append("|---|---|---|---|")
        for n in names:
            spec = TOOL_REGISTRY[n]
            kind = ("**confirm**" if spec.requires_confirm
                    else "**write**" if spec.mutating else "*read*")
            desc = (tools[n].description or "").replace("|", r"\|").strip()
            if len(desc) > 130:
                desc = desc[:127].rstrip() + "..."
            out.append(f"| `{n}` | {_access(spec)} | {kind} | {desc} |")

    missing = sorted(set(tools) - seen)
    if missing:  # a new tool that matches no group keyword
        out.append("\n## Other\n")
        out.append("| Tool | Access | Type | Description |")
        out.append("|---|---|---|---|")
        for n in missing:
            spec = TOOL_REGISTRY[n]
            kind = ("**confirm**" if spec.requires_confirm
                    else "**write**" if spec.mutating else "*read*")
            out.append(f"| `{n}` | {_access(spec)} | {kind} | {tools[n].description or ''} |")

    out.append(FOOTER)
    return "\n".join(out)


if __name__ == "__main__":
    content = render()
    if "--check" in sys.argv:
        current = OUT.read_text() if OUT.exists() else ""
        if current != content:
            print(f"{OUT} is out of date; run: python scripts/gen_tool_docs.py")
            sys.exit(1)
        print(f"{OUT} is up to date ({len(TOOL_REGISTRY)} tools)")
    else:
        OUT.write_text(content)
        print(f"wrote {OUT} ({len(TOOL_REGISTRY)} tools)")
