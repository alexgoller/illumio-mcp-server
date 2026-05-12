"""Tests for ToolContext dataclass."""
import pytest
from illumio_mcp.context import ToolContext


def test_tool_context_holds_pce_and_mode():
    sentinel_pce = object()
    ctx = ToolContext(pce=sentinel_pce, is_stdio=True)
    assert ctx.pce is sentinel_pce
    assert ctx.is_stdio is True


def test_tool_context_is_stdio_required():
    """is_stdio is required; we never want an ambiguous context."""
    with pytest.raises(TypeError):
        ToolContext(pce=object())  # missing is_stdio


def test_tool_context_can_be_extended_with_kwargs():
    """Future fields (user_sub, role, etc.) can be added as kwargs without
    breaking call sites that build a stdio context."""
    ctx = ToolContext(pce=object(), is_stdio=True)
    # If/when we add fields with defaults, existing callers must keep working.
    assert ctx.is_stdio is True


def test_tool_context_user_fields_default_to_none():
    """Stdio call sites construct ToolContext without auth fields; they must
    default to None so we can branch on them later."""
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.user_sub is None
    assert ctx.user_iss is None


def test_tool_context_can_carry_authenticated_user():
    ctx = ToolContext(pce=object(), is_stdio=False, user_sub="user-42", user_iss="https://idp")
    assert ctx.user_sub == "user-42"
    assert ctx.user_iss == "https://idp"


def test_tool_context_pce_can_be_none():
    """A user without registered PCE creds gets ctx.pce=None."""
    ctx = ToolContext(pce=None, is_stdio=False, user_sub="u", user_iss="i")
    assert ctx.pce is None


def test_tool_context_keystore_default_none():
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.keystore is None


def test_tool_context_can_carry_keystore():
    sentinel = object()
    ctx = ToolContext(pce=None, is_stdio=False, user_sub="u", user_iss="i", keystore=sentinel)
    assert ctx.keystore is sentinel


def test_tool_context_user_role_default_none():
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.user_role is None


def test_tool_context_carries_user_role_audit_request_id():
    sentinel_audit = object()
    ctx = ToolContext(
        pce=None,
        is_stdio=False,
        user_sub="u",
        user_iss="i",
        user_role="reader",
        audit_log=sentinel_audit,
        request_id="req-abc",
    )
    assert ctx.user_role == "reader"
    assert ctx.audit_log is sentinel_audit
    assert ctx.request_id == "req-abc"
