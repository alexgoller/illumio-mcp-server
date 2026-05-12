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
