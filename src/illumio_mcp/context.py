"""ToolContext: the per-call object every tool handler receives.

In Phase 1 it carried PCE + is_stdio. Phase 3a adds authenticated user
identity for the HTTP path. Stdio code constructs ToolContext as before;
the new fields default to None.
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
    user_sub: str | None = None  # IdP `sub` claim (None in stdio mode)
    user_iss: str | None = None  # IdP `iss` claim (None in stdio mode)
