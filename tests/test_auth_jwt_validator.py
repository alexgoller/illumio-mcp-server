"""Tests for JWTValidator. Uses a self-generated RSA key to sign test tokens
so we don't need a real OIDC provider."""
import time
import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from illumio_mcp.auth.config import OAuthConfig
from illumio_mcp.auth.jwt_validator import (
    JWTValidator,
    AuthenticatedUser,
    InvalidTokenError,
)


# ----- shared fixtures: an RSA key, a key resolver, a default config -----

@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def public_key_pem(rsa_key):
    return rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="module")
def private_key_pem(rsa_key):
    return rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def cfg():
    return OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url="https://mcp.test",
    )


@pytest.fixture(scope="module")
def validator(cfg, public_key_pem):
    """Validator with a static public-key resolver, no JWKS network calls."""
    return JWTValidator(cfg, key_resolver=lambda kid: public_key_pem)


def _mint(private_key_pem, **overrides):
    """Helper: produce a signed JWT with overridable claims."""
    claims = {
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": "user-42",
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        **overrides,
    }
    return pyjwt.encode(claims, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


# ----- happy path -----

def test_valid_token_returns_authenticated_user(validator, private_key_pem):
    token = _mint(private_key_pem)
    user = validator.validate(token)
    assert isinstance(user, AuthenticatedUser)
    assert user.sub == "user-42"
    assert user.iss == "https://idp.test/o"
    assert "illumio-mcp.use" in user.scopes


def test_authenticated_user_carries_groups_claim(validator, private_key_pem):
    token = _mint(private_key_pem, groups=["sg-illumio-mcp-readonly", "sg-net-eng"])
    user = validator.validate(token)
    assert user.groups == ["sg-illumio-mcp-readonly", "sg-net-eng"]


def test_authenticated_user_handles_missing_groups(validator, private_key_pem):
    token = _mint(private_key_pem)  # no groups
    user = validator.validate(token)
    assert user.groups == []


# ----- failure modes -----

def test_invalid_signature_rejected(cfg, private_key_pem):
    # Validator with a DIFFERENT public key than what signed the token
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pub = other_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    bad_validator = JWTValidator(cfg, key_resolver=lambda kid: other_pub)
    token = _mint(private_key_pem)
    with pytest.raises(InvalidTokenError):
        bad_validator.validate(token)


def test_wrong_issuer_rejected(validator, private_key_pem):
    token = _mint(private_key_pem, iss="https://attacker.example")
    with pytest.raises(InvalidTokenError, match="iss"):
        validator.validate(token)


def test_wrong_audience_rejected(validator, private_key_pem):
    token = _mint(private_key_pem, aud="some-other-resource")
    with pytest.raises(InvalidTokenError, match="aud"):
        validator.validate(token)


def test_expired_token_rejected(validator, private_key_pem):
    token = _mint(private_key_pem, exp=int(time.time()) - 60)
    with pytest.raises(InvalidTokenError, match="exp"):
        validator.validate(token)


def test_missing_required_scope_rejected(validator, private_key_pem):
    token = _mint(private_key_pem, scope="some-other-scope")
    with pytest.raises(InvalidTokenError, match="scope"):
        validator.validate(token)


def test_scope_can_be_a_list_or_space_separated(validator, private_key_pem):
    """OIDC IdPs vary: Entra uses space-separated string, Okta uses list. Both work."""
    list_token = _mint(private_key_pem, scope=["illumio-mcp.use", "openid"])
    space_token = _mint(private_key_pem, scope="openid illumio-mcp.use profile")
    assert validator.validate(list_token).sub == "user-42"
    assert validator.validate(space_token).sub == "user-42"


def test_garbage_token_rejected(validator):
    with pytest.raises(InvalidTokenError):
        validator.validate("not-a-jwt")
