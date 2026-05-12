"""ToolSpec: per-tool metadata used by the dispatcher and Phase 3 authz.

In Phase 1 this metadata is recorded but only one consumer reads it (a CI test
that asserts every tool has explicit role assignment). Phase 3 authz middleware
will read `roles`, `mutating`, `requires_confirm`, and `unscopable` to decide
whether to allow a call.
"""
from dataclasses import dataclass
from typing import Callable, Literal

Role = Literal["reader", "operator", "admin"]
READER: Role = "reader"
OPERATOR: Role = "operator"
ADMIN: Role = "admin"
ALL_ROLES: frozenset[Role] = frozenset({READER, OPERATOR, ADMIN})

_VALID_ROLES = ALL_ROLES


@dataclass(frozen=True)
class ToolSpec:
    """Metadata for one MCP tool.

    Attributes:
        handler: The handler callable. Signature: (ctx, arguments) -> list.
        roles: Set of roles permitted to call this tool. Must be non-empty.
        mutating: True if the tool changes PCE state (create/update/delete/provision).
        requires_confirm: True if a step-up confirm token is required (Phase 3d).
            Implies mutating=True.
        unscopable: True if the tool returns PCE-wide data that cannot be safely
            filtered to a user's allowed label scopes (Phase 3c).
        requires_pce: True if the tool needs ctx.pce to be non-None. Defaults
            True. Set to False for credential-management tools that run before
            a user has onboarded (e.g., register-pce-credentials).
    """
    handler: Callable
    roles: frozenset[Role] | set[Role]
    mutating: bool = False
    requires_confirm: bool = False
    unscopable: bool = False
    requires_pce: bool = True

    def __post_init__(self):
        if not self.roles:
            raise ValueError("ToolSpec must have at least one role (default-deny)")
        unknown = set(self.roles) - _VALID_ROLES
        if unknown:
            raise ValueError(f"ToolSpec has unknown role(s): {sorted(unknown)}")
        if self.requires_confirm and not self.mutating:
            raise ValueError("requires_confirm is only valid for mutating tools")
        # Freeze the role set so it can't be mutated post-construction
        object.__setattr__(self, "roles", frozenset(self.roles))
