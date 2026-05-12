"""Map JWT group claims to internal MCP roles.

Three internal roles defined in `illumio_mcp.registry`: reader, operator, admin.
Each role has a list of group names (from the IdP) that grant it. A user's
effective role is the HIGHEST role any of their groups qualifies for
(admin > operator > reader).

Configuration is env-driven, comma-separated. Empty config = no role match
(callers should also configure MCP_ROLE_DEFAULT for fallback behavior).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable

from ..registry import Role, READER, OPERATOR, ADMIN


@dataclass(frozen=True)
class RoleConfig:
    admin_groups: list[str] = field(default_factory=list)
    operator_groups: list[str] = field(default_factory=list)
    reader_groups: list[str] = field(default_factory=list)
    default_role: Role | None = None


def _split(env_value: str | None) -> list[str]:
    if not env_value:
        return []
    return [g.strip() for g in env_value.split(",") if g.strip()]


def load_role_config_from_env() -> RoleConfig:
    """Read MCP_ROLE_GROUPS_{ADMIN,OPERATOR,READER} + MCP_ROLE_DEFAULT."""
    default = os.getenv("MCP_ROLE_DEFAULT") or None
    if default and default not in (READER, OPERATOR, ADMIN):
        raise ValueError(
            f"MCP_ROLE_DEFAULT must be one of {READER!r}, {OPERATOR!r}, {ADMIN!r}; got {default!r}"
        )
    return RoleConfig(
        admin_groups=_split(os.getenv("MCP_ROLE_GROUPS_ADMIN")),
        operator_groups=_split(os.getenv("MCP_ROLE_GROUPS_OPERATOR")),
        reader_groups=_split(os.getenv("MCP_ROLE_GROUPS_READER")),
        default_role=default,
    )


def map_user_role(user_groups: Iterable[str], config: RoleConfig) -> Role | None:
    """Return the highest role the user qualifies for, or `default_role`, or None.

    Highest-first order: admin > operator > reader.
    """
    groups = set(user_groups)
    if any(g in groups for g in config.admin_groups):
        return ADMIN
    if any(g in groups for g in config.operator_groups):
        return OPERATOR
    if any(g in groups for g in config.reader_groups):
        return READER
    return config.default_role
