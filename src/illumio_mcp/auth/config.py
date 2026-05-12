"""OAuthConfig: env-loaded configuration for the OAuth Resource Server."""
from __future__ import annotations

import os
from dataclasses import dataclass


class MissingOAuthConfigError(RuntimeError):
    """Raised when required OAuth env vars are not set and DEV_INSECURE is off."""


@dataclass(frozen=True)
class OAuthConfig:
    """Resolved OAuth Resource Server configuration.

    Attributes:
        issuer: Expected `iss` claim value (e.g. https://login.microsoftonline.com/<tid>/v2.0).
        jwks_url: Where to fetch the IdP's signing keys.
        audience: Expected `aud` claim value (this server's resource indicator).
        required_scope: Scope the JWT must contain to access /mcp (e.g. illumio-mcp.use).
        resource_url: Public URL of this resource server, used in PRM metadata.
    """
    issuer: str
    jwks_url: str
    audience: str
    required_scope: str
    resource_url: str


_REQUIRED = ("MCP_OAUTH_ISSUER", "MCP_OAUTH_JWKS_URL", "MCP_OAUTH_AUDIENCE", "MCP_PUBLIC_URL")


def load_oauth_config_from_env() -> OAuthConfig:
    """Build OAuthConfig from environment. Raises MissingOAuthConfigError if any
    required var is unset (lists ALL missing vars, not just the first)."""
    missing = [name for name in _REQUIRED if not os.getenv(name)]
    if missing:
        raise MissingOAuthConfigError(
            "Missing required OAuth env vars: " + ", ".join(missing)
            + ". Set them or set MCP_DEV_INSECURE=1 to bypass auth (dev only)."
        )
    return OAuthConfig(
        issuer=os.environ["MCP_OAUTH_ISSUER"],
        jwks_url=os.environ["MCP_OAUTH_JWKS_URL"],
        audience=os.environ["MCP_OAUTH_AUDIENCE"],
        required_scope=os.getenv("MCP_OAUTH_REQUIRED_SCOPE", "illumio-mcp.use"),
        resource_url=os.environ["MCP_PUBLIC_URL"],
    )


def is_dev_insecure() -> bool:
    """True iff MCP_DEV_INSECURE is set to a truthy value (`1`/`true`/`yes`)."""
    return os.getenv("MCP_DEV_INSECURE", "").lower() in ("1", "true", "yes")
