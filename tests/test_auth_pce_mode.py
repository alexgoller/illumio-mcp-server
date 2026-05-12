"""Tests for PCE mode env loading."""
import pytest
from illumio_mcp.auth.pce_mode import (
    load_pce_mode_from_env, is_shared_mode, PER_USER, SHARED,
)


def test_constants_are_distinct_strings():
    assert PER_USER == "per_user"
    assert SHARED == "shared"
    assert PER_USER != SHARED


def test_default_is_per_user(monkeypatch):
    monkeypatch.delenv("MCP_PCE_MODE", raising=False)
    assert load_pce_mode_from_env() == PER_USER


def test_explicit_per_user(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "per_user")
    assert load_pce_mode_from_env() == PER_USER


def test_explicit_shared(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "shared")
    assert load_pce_mode_from_env() == SHARED


def test_unknown_value_raises(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "bogus")
    with pytest.raises(ValueError, match="MCP_PCE_MODE"):
        load_pce_mode_from_env()


def test_is_shared_mode_helper():
    assert is_shared_mode("shared") is True
    assert is_shared_mode("per_user") is False
    assert is_shared_mode(None) is False
