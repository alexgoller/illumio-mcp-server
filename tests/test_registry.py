"""Tests for ToolSpec and role constants."""
import pytest
from illumio_mcp.registry import (
    ToolSpec, Role, READER, OPERATOR, ADMIN, ALL_ROLES,
)


def _h(ctx, arguments):
    return []


def test_role_constants_are_distinct_strings():
    assert {READER, OPERATOR, ADMIN} == {"reader", "operator", "admin"}


def test_all_roles_contains_three():
    assert ALL_ROLES == {READER, OPERATOR, ADMIN}


def test_toolspec_requires_non_empty_roles():
    """Default-deny: a tool with no roles is a configuration error."""
    with pytest.raises(ValueError, match="at least one role"):
        ToolSpec(handler=_h, roles=set())


def test_toolspec_rejects_unknown_role():
    with pytest.raises(ValueError, match="unknown role"):
        ToolSpec(handler=_h, roles={"superuser"})  # type: ignore[arg-type]


def test_toolspec_defaults():
    spec = ToolSpec(handler=_h, roles={ADMIN})
    assert spec.mutating is False
    assert spec.requires_confirm is False
    assert spec.unscopable is False


def test_toolspec_requires_confirm_implies_mutating():
    """requires_confirm only makes sense for mutating tools; we enforce it
    so a typo can't silently expose a confirm-required-but-not-mutating tool."""
    with pytest.raises(ValueError, match="mutating"):
        ToolSpec(handler=_h, roles={ADMIN}, requires_confirm=True)


def test_toolspec_requires_pce_default_true():
    spec = ToolSpec(handler=_h, roles={ADMIN})
    assert spec.requires_pce is True


def test_toolspec_can_opt_out_of_pce():
    spec = ToolSpec(handler=_h, roles={ADMIN}, requires_pce=False)
    assert spec.requires_pce is False
