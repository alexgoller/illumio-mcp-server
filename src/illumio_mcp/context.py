"""ToolContext: the per-call object every tool handler receives.

In Phase 1 (this refactor) it carries only the PCE client and a flag indicating
whether we're running under stdio (the default today). Phases 2 and 3 will add
user identity, role, scope, and request-id fields. Existing call sites should
not break when those are added — they all have defaults.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    """Everything a tool handler needs that is *not* the tool's own arguments.

    Build one per request (HTTP) or once at startup (stdio) and pass it to
    every handler. Handlers MUST read PCE from `ctx.pce` and never call
    process-global PCE accessors.
    """
    pce: object  # illumio.PolicyComputeEngine, but kept untyped to avoid import here
    is_stdio: bool
