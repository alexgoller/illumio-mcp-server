"""RFC 9728 Protected Resource Metadata for the MCP HTTP transport.

Served at /.well-known/oauth-protected-resource. Tells MCP clients where the
Authorization Server is so they can run PKCE auth code flow against it.
"""
from .config import OAuthConfig


def build_prm_document(config: OAuthConfig) -> dict:
    """Construct the RFC 9728 document for the configured resource server.

    Per the MCP 2025-06-18 spec, the only required fields are:
      - resource: URL of this resource server
      - authorization_servers: list of issuer URLs the client should use
    We also include bearer_methods_supported and scopes_supported as a hint to
    the client that header-based bearer tokens are accepted and which scope is
    required.
    """
    return {
        "resource": config.resource_url,
        "authorization_servers": [config.issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [config.required_scope],
    }
