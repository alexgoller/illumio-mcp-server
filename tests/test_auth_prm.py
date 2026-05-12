"""Tests for the RFC 9728 Protected Resource Metadata document."""
import json

from illumio_mcp.auth.config import OAuthConfig
from illumio_mcp.auth.prm import build_prm_document


def test_prm_document_has_required_fields():
    cfg = OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url="https://mcp.test",
    )
    doc = build_prm_document(cfg)
    assert doc["resource"] == "https://mcp.test"
    assert doc["authorization_servers"] == ["https://idp.test/o"]
    assert doc["bearer_methods_supported"] == ["header"]
    assert doc["scopes_supported"] == ["illumio-mcp.use"]


def test_prm_document_serializes_as_json():
    cfg = OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url="https://mcp.test",
    )
    doc = build_prm_document(cfg)
    # Round-trips cleanly
    assert json.loads(json.dumps(doc)) == doc
