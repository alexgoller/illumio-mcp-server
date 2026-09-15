"""Write tools must advertise that the client will pause for approval.

An approval prompt is invisible to the model: a gated call simply stops
producing output, which reads as a hung server, and the reflex is to retry --
queueing a second approval for a PCE write. Derived from TOOL_REGISTRY rather
than a hand-kept list, since a second list of write tools is a third place to
forget, which is how tools/list drifted from the registry once already.
"""
import asyncio
import pytest

from illumio_mcp.server import handle_list_tools, MUTATING_TOOL_NOTE
from illumio_mcp.tools import TOOL_REGISTRY


@pytest.fixture(scope="module")
def tools():
    return asyncio.run(handle_list_tools())


def test_every_mutating_tool_warns_about_approval(tools):
    missing = [t.name for t in tools
               if TOOL_REGISTRY[t.name].mutating
               and "WRITE OPERATION" not in (t.description or "")]
    assert not missing, f"mutating tools with no approval note: {missing}"


def test_read_only_tools_are_not_annotated(tools):
    wrong = [t.name for t in tools
             if not TOOL_REGISTRY[t.name].mutating
             and "WRITE OPERATION" in (t.description or "")]
    assert not wrong, f"read-only tools wrongly annotated: {wrong}"


def test_confirm_tools_explain_the_two_step_flow(tools):
    confirm = [t for t in tools if TOOL_REGISTRY[t.name].requires_confirm]
    assert confirm, "expected at least one confirm-gated tool"
    for tool in confirm:
        assert "confirm token" in tool.description


def test_annotation_preserves_the_original_description(tools):
    """The note is appended, not substituted -- losing the real description
    would break tool selection to fix a usability hint."""
    workloads = next(t for t in tools if t.name == "create-workload")
    assert workloads.description.endswith(MUTATING_TOOL_NOTE)
    assert len(workloads.description) > len(MUTATING_TOOL_NOTE)


def test_non_vacuous(tools):
    mutating = [t for t in tools if TOOL_REGISTRY[t.name].mutating]
    assert len(mutating) >= 15, f"suspiciously few mutating tools: {len(mutating)}"
