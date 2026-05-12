"""ToolContext: the per-call object every tool handler receives.

Phase 3b: `pce` is now Optional — users who haven't onboarded yet have no PCE
client. The dispatcher only routes them to credential-management tools
(`requires_pce=False`). `keystore` is provided so those tools can write rows.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    """Everything a tool handler needs that is *not* the tool's own arguments.

    Build one per request (HTTP) or once at startup (stdio) and pass it to
    every handler. Handlers MUST read PCE from `ctx.pce` and never call
    process-global PCE accessors. If `ctx.pce is None`, the dispatcher will
    have already refused to route any tool with `requires_pce=True`.
    """
    pce: object | None  # illumio.PolicyComputeEngine, or None if user hasn't onboarded
    is_stdio: bool
    user_sub: str | None = None
    user_iss: str | None = None
    keystore: object | None = None  # auth.keystore.KeyStore in HTTP mode; None in stdio
