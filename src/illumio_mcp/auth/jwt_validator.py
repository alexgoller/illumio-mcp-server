"""JWTValidator: validates Bearer tokens against the configured IdP.

Two key resolution paths:

- Production: PyJWKClient fetches the JWKS from the configured URL, caches it,
  and refreshes on `kid` mismatch.
- Tests / dev: pass a `key_resolver` callable that returns the public key for a
  given `kid` directly. Lets us avoid network calls.

Returns AuthenticatedUser on success; raises InvalidTokenError with a short
reason on failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import jwt as pyjwt
from jwt import PyJWKClient

from .config import OAuthConfig


class InvalidTokenError(Exception):
    """Raised when a JWT fails validation. Message includes the short reason."""


@dataclass(frozen=True)
class AuthenticatedUser:
    """Identity extracted from a validated JWT."""
    sub: str
    iss: str
    scopes: list[str]
    groups: list[str] = field(default_factory=list)
    # OIDC `auth_time` (seconds since epoch) — when the end-user actually
    # authenticated, as opposed to `iat` (when this token was minted, possibly
    # from a refresh token). Optional in OIDC, so None when the IdP omits it.
    # Consumed by the /confirm fresh-auth gate.
    auth_time: int | None = None


def _normalize_scopes(scope_claim) -> list[str]:
    """OIDC IdPs send `scope` as either a space-separated string (Entra) or
    a list of strings (Okta). Normalize to a list."""
    if isinstance(scope_claim, list):
        return list(scope_claim)
    if isinstance(scope_claim, str):
        return scope_claim.split()
    return []


def _normalize_auth_time(value) -> int | None:
    """Coerce the OIDC `auth_time` claim to an int, or None if unusable.

    Spec'd as a NumericDate, but IdPs have been observed sending it as a string.
    A malformed value is treated as absent rather than raising: `auth_time` is
    not required for token validity, and the /confirm fresh-auth gate already
    fails closed on None.
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_groups(token_payload: dict) -> list[str]:
    """Extract groups/roles from any of the well-known claim names."""
    for key in ("groups", "roles"):
        value = token_payload.get(key)
        if isinstance(value, list):
            return [str(v) for v in value]
    return []


class JWTValidator:
    """Local JWT validator. Stateless after construction."""

    def __init__(
        self,
        config: OAuthConfig,
        *,
        key_resolver: Callable[[str | None], bytes] | None = None,
        algorithms: tuple[str, ...] = ("RS256", "ES256"),
    ):
        self._config = config
        self._algorithms = list(algorithms)
        if key_resolver is not None:
            self._resolve_key = key_resolver
        else:
            jwks_client = PyJWKClient(config.jwks_url)
            self._resolve_key = lambda kid: jwks_client.get_signing_key(kid).key

    def validate(self, token: str) -> AuthenticatedUser:
        try:
            unverified_header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError as e:
            raise InvalidTokenError(f"malformed token: {e}") from e

        kid = unverified_header.get("kid")
        try:
            key = self._resolve_key(kid)
        except Exception as e:
            raise InvalidTokenError(f"cannot resolve signing key: {e}") from e

        try:
            payload = pyjwt.decode(
                token,
                key=key,
                algorithms=self._algorithms,
                audience=self._config.audience,
                issuer=self._config.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except pyjwt.InvalidSignatureError as e:
            raise InvalidTokenError(f"invalid signature: {e}") from e
        except pyjwt.InvalidIssuerError as e:
            raise InvalidTokenError(f"iss mismatch: {e}") from e
        except pyjwt.InvalidAudienceError as e:
            raise InvalidTokenError(f"aud mismatch: {e}") from e
        except pyjwt.ExpiredSignatureError as e:
            raise InvalidTokenError(f"exp passed: {e}") from e
        except pyjwt.PyJWTError as e:
            raise InvalidTokenError(f"invalid token: {e}") from e

        scopes = _normalize_scopes(payload.get("scope") or payload.get("scp"))
        if self._config.required_scope not in scopes:
            raise InvalidTokenError(
                f"missing required scope {self._config.required_scope!r}; got {scopes!r}"
            )

        return AuthenticatedUser(
            sub=str(payload["sub"]),
            iss=str(payload["iss"]),
            scopes=scopes,
            groups=_normalize_groups(payload),
            auth_time=_normalize_auth_time(payload.get("auth_time")),
        )
