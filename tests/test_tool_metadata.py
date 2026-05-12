"""Guard tests for the TOOL_REGISTRY.

These run fast (no PCE) and exist to keep the registry self-consistent as new
tools are added. If you're tempted to skip one, write a comment in this file
explaining why instead.
"""
import inspect
import re

from illumio_mcp.tools import TOOL_REGISTRY
from illumio_mcp.registry import ToolSpec, ALL_ROLES


def test_every_tool_has_a_toolspec():
    """If this fails, someone added a handler to TOOL_HANDLERS by mistake or
    forgot to migrate to TOOL_REGISTRY."""
    for name, spec in TOOL_REGISTRY.items():
        assert isinstance(spec, ToolSpec), f"{name!r} is not a ToolSpec"


def test_every_tool_has_explicit_roles():
    for name, spec in TOOL_REGISTRY.items():
        assert spec.roles, f"{name!r} has no roles assigned (default-deny violated)"
        assert set(spec.roles).issubset(ALL_ROLES), \
            f"{name!r} has unknown roles: {spec.roles}"


def test_handlers_have_ctx_first_argument():
    """Every handler must accept (ctx, arguments). Catches missed conversions."""
    for name, spec in TOOL_REGISTRY.items():
        sig = inspect.signature(spec.handler)
        params = list(sig.parameters.keys())
        assert len(params) >= 2, f"{name!r} handler has fewer than 2 params: {params}"
        assert params[0] == "ctx", f"{name!r} handler's first param is {params[0]!r}, expected 'ctx'"


def test_destructive_tool_names_are_marked_mutating():
    """A tool whose name starts with create-/update-/delete-/provision-
    must be `mutating=True`. Catches a contributor adding e.g. delete-foo
    and forgetting the mutating flag."""
    pattern = re.compile(r"^(create|update|delete|provision)-")
    for name, spec in TOOL_REGISTRY.items():
        if pattern.match(name):
            assert spec.mutating, f"{name!r} looks destructive but mutating=False"


def test_ringfence_batch_requires_confirm():
    """ringfence-batch and provision-policy are explicit confirm-required tools
    per spec §9. If the metadata gets edited by mistake, this catches it."""
    for name in ("provision-policy", "ringfence-batch"):
        spec = TOOL_REGISTRY[name]
        assert spec.requires_confirm, f"{name!r} should require confirm token"


def test_count_matches_expected():
    """Sanity check: tool count is stable. Bump this when you intentionally
    add or remove a tool."""
    assert len(TOOL_REGISTRY) == 46, \
        f"Tool count drifted to {len(TOOL_REGISTRY)}; update this test if intentional"
