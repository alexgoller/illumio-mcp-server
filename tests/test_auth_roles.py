"""Tests for role config and JWT groups → role mapping."""
import pytest

from illumio_mcp.auth.roles import (
    RoleConfig, load_role_config_from_env, map_user_role,
)
from illumio_mcp.registry import READER, OPERATOR, ADMIN


def test_role_config_holds_lists():
    cfg = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )
    assert "sg-admin" in cfg.admin_groups


def test_load_from_env_happy_path(monkeypatch):
    monkeypatch.setenv("MCP_ROLE_GROUPS_ADMIN", "sg-admin")
    monkeypatch.setenv("MCP_ROLE_GROUPS_OPERATOR", "sg-op,sg-admin")
    monkeypatch.setenv("MCP_ROLE_GROUPS_READER", "sg-read,sg-op,sg-admin")
    monkeypatch.delenv("MCP_ROLE_DEFAULT", raising=False)
    cfg = load_role_config_from_env()
    assert cfg.admin_groups == ["sg-admin"]
    assert cfg.operator_groups == ["sg-op", "sg-admin"]
    assert cfg.reader_groups == ["sg-read", "sg-op", "sg-admin"]
    assert cfg.default_role is None


def test_load_from_env_default_role(monkeypatch):
    monkeypatch.setenv("MCP_ROLE_GROUPS_ADMIN", "sg-admin")
    monkeypatch.setenv("MCP_ROLE_GROUPS_OPERATOR", "sg-op")
    monkeypatch.setenv("MCP_ROLE_GROUPS_READER", "sg-read")
    monkeypatch.setenv("MCP_ROLE_DEFAULT", "reader")
    cfg = load_role_config_from_env()
    assert cfg.default_role == "reader"


def test_load_from_env_blank_envs_ok(monkeypatch):
    """All-empty env produces empty lists, not None — keeps mapping logic simple."""
    monkeypatch.delenv("MCP_ROLE_GROUPS_ADMIN", raising=False)
    monkeypatch.delenv("MCP_ROLE_GROUPS_OPERATOR", raising=False)
    monkeypatch.delenv("MCP_ROLE_GROUPS_READER", raising=False)
    monkeypatch.delenv("MCP_ROLE_DEFAULT", raising=False)
    cfg = load_role_config_from_env()
    assert cfg.admin_groups == []
    assert cfg.operator_groups == []
    assert cfg.reader_groups == []


def _cfg(default_role=None):
    return RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=default_role,
    )


def test_admin_group_wins_when_user_has_all():
    cfg = _cfg()
    assert map_user_role(["sg-read", "sg-op", "sg-admin"], cfg) == ADMIN


def test_operator_when_only_operator_group():
    cfg = _cfg()
    assert map_user_role(["sg-op"], cfg) == OPERATOR


def test_reader_when_only_reader_group():
    cfg = _cfg()
    assert map_user_role(["sg-read"], cfg) == READER


def test_no_role_when_no_match_and_no_default():
    cfg = _cfg(default_role=None)
    assert map_user_role(["sg-other"], cfg) is None


def test_default_role_used_when_no_group_match():
    cfg = _cfg(default_role=READER)
    assert map_user_role(["sg-other"], cfg) == READER


def test_empty_groups_with_no_default_returns_none():
    cfg = _cfg(default_role=None)
    assert map_user_role([], cfg) is None
