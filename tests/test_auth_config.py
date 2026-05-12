"""Tests for OAuthConfig env loading."""
import pytest
from illumio_mcp.auth.config import OAuthConfig, load_oauth_config_from_env, MissingOAuthConfigError


def test_oauth_config_holds_required_fields():
    cfg = OAuthConfig(
        issuer="https://idp.example/o",
        jwks_url="https://idp.example/o/.well-known/jwks.json",
        audience="mcp.example",
        required_scope="illumio-mcp.use",
        resource_url="https://mcp.example",
    )
    assert cfg.issuer == "https://idp.example/o"
    assert cfg.audience == "mcp.example"


def test_load_from_env_happy_path(monkeypatch):
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://idp.example/o")
    monkeypatch.setenv("MCP_OAUTH_JWKS_URL", "https://idp.example/o/.well-known/jwks.json")
    monkeypatch.setenv("MCP_OAUTH_AUDIENCE", "mcp.example")
    monkeypatch.setenv("MCP_OAUTH_REQUIRED_SCOPE", "illumio-mcp.use")
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://mcp.example")
    cfg = load_oauth_config_from_env()
    assert cfg.issuer == "https://idp.example/o"
    assert cfg.required_scope == "illumio-mcp.use"
    assert cfg.resource_url == "https://mcp.example"


def test_load_from_env_required_scope_default(monkeypatch):
    """required_scope defaults to 'illumio-mcp.use' if not set."""
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://idp.example/o")
    monkeypatch.setenv("MCP_OAUTH_JWKS_URL", "https://idp.example/o/.well-known/jwks.json")
    monkeypatch.setenv("MCP_OAUTH_AUDIENCE", "mcp.example")
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://mcp.example")
    monkeypatch.delenv("MCP_OAUTH_REQUIRED_SCOPE", raising=False)
    cfg = load_oauth_config_from_env()
    assert cfg.required_scope == "illumio-mcp.use"


def test_load_from_env_missing_required_raises(monkeypatch):
    monkeypatch.delenv("MCP_OAUTH_ISSUER", raising=False)
    monkeypatch.delenv("MCP_OAUTH_JWKS_URL", raising=False)
    monkeypatch.delenv("MCP_OAUTH_AUDIENCE", raising=False)
    monkeypatch.delenv("MCP_PUBLIC_URL", raising=False)
    with pytest.raises(MissingOAuthConfigError) as exc_info:
        load_oauth_config_from_env()
    msg = str(exc_info.value)
    # Mentions every missing var so the operator can fix all at once
    assert "MCP_OAUTH_ISSUER" in msg
    assert "MCP_OAUTH_AUDIENCE" in msg


def test_is_dev_insecure(monkeypatch):
    monkeypatch.setenv("MCP_DEV_INSECURE", "1")
    from illumio_mcp.auth.config import is_dev_insecure
    assert is_dev_insecure() is True
    monkeypatch.setenv("MCP_DEV_INSECURE", "0")
    assert is_dev_insecure() is False
    monkeypatch.delenv("MCP_DEV_INSECURE", raising=False)
    assert is_dev_insecure() is False
