"""ConfirmTokenManager — HMAC-signed single-use tokens for mutating tools.

Wire format: `<base64url(payload_json)>.<base64url(hmac_sha256)>`
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from secrets import token_bytes


class MissingConfirmHmacKeyError(RuntimeError):
    pass


class InvalidConfirmTokenError(Exception):
    pass


_KEY_BYTES = 32


@dataclass(frozen=True)
class ConfirmTokenClaims:
    sub: str
    tool: str
    params_hash: str
    jti: str
    exp: int


def generate_hmac_key() -> bytes:
    return token_bytes(_KEY_BYTES)


def load_hmac_key_from_env() -> bytes:
    raw = os.getenv("MCP_CONFIRM_HMAC_KEY")
    if not raw:
        raise MissingConfirmHmacKeyError(
            "MCP_CONFIRM_HMAC_KEY env var is required (32-byte base64). "
            "Generate with: python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'"
        )
    try:
        key = base64.b64decode(raw)
    except Exception as e:
        raise ValueError(f"MCP_CONFIRM_HMAC_KEY is not valid base64: {e}") from e
    if len(key) != _KEY_BYTES:
        raise ValueError(f"MCP_CONFIRM_HMAC_KEY must decode to exactly 32 bytes, got {len(key)}")
    return key


def canonical_params_hash(params: dict) -> str:
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


class ConfirmTokenManager:
    """Stateless HMAC-token mint/verify."""

    def __init__(self, hmac_key: bytes, *, ttl_seconds: int = 120):
        if len(hmac_key) != _KEY_BYTES:
            raise ValueError(f"HMAC key must be {_KEY_BYTES} bytes, got {len(hmac_key)}")
        self._key = hmac_key
        self._ttl = ttl_seconds

    def mint(self, *, sub: str, tool: str, params_hash: str) -> str:
        claims = {
            "sub": sub,
            "tool": tool,
            "params_hash": params_hash,
            "jti": uuid.uuid4().hex,
            "exp": int(time.time()) + self._ttl,
        }
        payload = _b64url_encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64url_encode(hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest())
        return f"{payload}.{sig}"

    def verify(self, token: str, *, sub: str, tool: str, params_hash: str) -> ConfirmTokenClaims:
        try:
            payload_b64, sig_b64 = token.split(".")
        except ValueError as e:
            raise InvalidConfirmTokenError(f"malformed token: {e}") from e

        expected_sig = _b64url_encode(
            hmac.new(self._key, payload_b64.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(sig_b64, expected_sig):
            raise InvalidConfirmTokenError("invalid signature")

        try:
            claims_dict = json.loads(_b64url_decode(payload_b64))
        except Exception as e:
            raise InvalidConfirmTokenError(f"malformed payload: {e}") from e

        if claims_dict.get("exp", 0) <= int(time.time()):
            raise InvalidConfirmTokenError("token expired")
        if claims_dict.get("sub") != sub:
            raise InvalidConfirmTokenError(f"sub mismatch (token={claims_dict.get('sub')!r}, caller={sub!r})")
        if claims_dict.get("tool") != tool:
            raise InvalidConfirmTokenError(f"tool mismatch (token={claims_dict.get('tool')!r}, caller={tool!r})")
        if claims_dict.get("params_hash") != params_hash:
            raise InvalidConfirmTokenError("params_hash mismatch")

        return ConfirmTokenClaims(
            sub=claims_dict["sub"],
            tool=claims_dict["tool"],
            params_hash=claims_dict["params_hash"],
            jti=claims_dict["jti"],
            exp=claims_dict["exp"],
        )
