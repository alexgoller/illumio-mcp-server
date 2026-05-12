"""Tests for ConfirmTokenManager (HMAC mint + verify)."""
import os
import time
import base64
import pytest

from illumio_mcp.auth.confirm import (
    ConfirmTokenManager,
    InvalidConfirmTokenError,
    canonical_params_hash,
    generate_hmac_key,
    load_hmac_key_from_env,
    MissingConfirmHmacKeyError,
)


@pytest.fixture
def mgr():
    return ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)


def _mint(mgr, **overrides):
    args = {
        "sub": "user-42",
        "tool": "provision-policy",
        "params_hash": "h" * 64,
    }
    args.update(overrides)
    return mgr.mint(**args)


def test_mint_then_verify_round_trip(mgr):
    token = _mint(mgr)
    claims = mgr.verify(token, sub="user-42", tool="provision-policy", params_hash="h" * 64)
    assert claims.sub == "user-42"
    assert claims.tool == "provision-policy"
    assert claims.jti  # non-empty


def test_verify_wrong_sub_rejected(mgr):
    token = _mint(mgr)
    with pytest.raises(InvalidConfirmTokenError, match="sub"):
        mgr.verify(token, sub="other-user", tool="provision-policy", params_hash="h" * 64)


def test_verify_wrong_tool_rejected(mgr):
    token = _mint(mgr)
    with pytest.raises(InvalidConfirmTokenError, match="tool"):
        mgr.verify(token, sub="user-42", tool="delete-workload", params_hash="h" * 64)


def test_verify_wrong_params_hash_rejected(mgr):
    token = _mint(mgr)
    with pytest.raises(InvalidConfirmTokenError, match="params"):
        mgr.verify(token, sub="user-42", tool="provision-policy", params_hash="x" * 64)


def test_verify_tampered_signature_rejected(mgr):
    token = _mint(mgr)
    # Flip a byte in the middle of the token
    parts = token.split(".")
    tampered_payload = parts[0][:-1] + ("a" if parts[0][-1] != "a" else "b")
    bad = tampered_payload + "." + parts[1]
    with pytest.raises(InvalidConfirmTokenError):
        mgr.verify(bad, sub="user-42", tool="provision-policy", params_hash="h" * 64)


def test_verify_expired_token_rejected():
    # Use a tiny TTL so we can wait past it.
    mgr = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=1)
    token = mgr.mint(sub="user-42", tool="provision-policy", params_hash="h" * 64)
    time.sleep(1.5)
    with pytest.raises(InvalidConfirmTokenError, match="expired"):
        mgr.verify(token, sub="user-42", tool="provision-policy", params_hash="h" * 64)


def test_verify_with_different_key_rejected():
    mgr_a = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)
    mgr_b = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)
    token = mgr_a.mint(sub="user-42", tool="provision-policy", params_hash="h" * 64)
    with pytest.raises(InvalidConfirmTokenError):
        mgr_b.verify(token, sub="user-42", tool="provision-policy", params_hash="h" * 64)


def test_canonical_params_hash_is_stable():
    h1 = canonical_params_hash({"a": 1, "b": [2, 3]})
    h2 = canonical_params_hash({"b": [2, 3], "a": 1})
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_canonical_params_hash_differs_for_different_params():
    assert canonical_params_hash({"a": 1}) != canonical_params_hash({"a": 2})


def test_load_hmac_key_from_env_happy_path(monkeypatch):
    raw = os.urandom(32)
    monkeypatch.setenv("MCP_CONFIRM_HMAC_KEY", base64.b64encode(raw).decode())
    assert load_hmac_key_from_env() == raw


def test_load_hmac_key_from_env_missing_raises(monkeypatch):
    monkeypatch.delenv("MCP_CONFIRM_HMAC_KEY", raising=False)
    with pytest.raises(MissingConfirmHmacKeyError):
        load_hmac_key_from_env()


def test_load_hmac_key_from_env_wrong_length_raises(monkeypatch):
    monkeypatch.setenv("MCP_CONFIRM_HMAC_KEY", base64.b64encode(b"only-16-bytes-aaa").decode())
    with pytest.raises(ValueError, match="32"):
        load_hmac_key_from_env()
