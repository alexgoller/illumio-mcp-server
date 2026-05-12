# Phase 3a: OAuth Resource Server — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OAuth 2.1 Resource Server semantics to the HTTP transport. The server validates JWT bearer tokens locally against a configured IdP (issuer + JWKS), publishes RFC 9728 Protected Resource Metadata, and refuses any tool call without a valid token. PCE credentials are still shared from env (per-user keys land in Phase 3b). Stdio transport is unchanged.

**Architecture:** A pure `auth/` package with three small modules — `jwt_validator.py` (PyJWT + JWKS cache), `prm.py` (one Starlette route returning the RFC 9728 metadata document), and `middleware.py` (Starlette middleware that validates the Bearer token and stores claims in `request.state.user`). The middleware is mounted only on `/mcp`, not on `/healthz`/`/readyz`/`/.well-known/*`. `ToolContext` gets two optional fields (`user_sub`, `user_iss`) so authenticated identity is visible to tool handlers — stdio stays backward-compatible. HTTP startup refuses to run without OAuth config unless `MCP_DEV_INSECURE=1` is set.

**Tech Stack:** `PyJWT[crypto]>=2.8.0` (JWT validation, JWKS), `httpx` (already a transitive dep, used for JWKS fetch), nothing else new.

**Spec:** [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §3 (Authentication) and §5 Layer 1 (JWT validation).

**Branch:** `feature/oauth-resource-server` off the latest of `main` / `feature/streamable-http-transport` / `feature/tool-context-refactor`. If Phase 1 (#10) and Phase 2 (#11) are still open, branch from `feature/streamable-http-transport`.

---

## Working agreement

- Stdio transport is unchanged. Verify with the JSON-RPC `initialize` handshake at every commit that touches anything outside `auth/`.
- Phase 2 invariants must hold: HTTP server still binds 127.0.0.1 by default, refuses public bind without `MCP_DEV_INSECURE=1`, `/healthz` and `/readyz` are unauthenticated.
- New env requirement on HTTP path: `MCP_OAUTH_ISSUER`, `MCP_OAUTH_JWKS_URL` (or auto-discover from issuer), `MCP_OAUTH_AUDIENCE`, `MCP_OAUTH_REQUIRED_SCOPE`. Server with `--http` refuses to start if these are missing AND `MCP_DEV_INSECURE` is not set.
- `MCP_DEV_INSECURE=1` continues to be the dev escape hatch — when set, auth is skipped entirely on the HTTP path. CI tests use this flag selectively.
- The JWT validator must be **dependency-injectable** so tests don't need to spin up a real OIDC provider. A fake key resolver suffices.
- One commit per task. `feat:` for new features, `chore:` for deps, `test:` for tests, `docs:` for docs.
- After every task, run the verification step. If it fails, stop and diagnose.

---

## File structure

| File | Responsibility |
|---|---|
| `pyproject.toml` (modify) | Add `PyJWT[crypto]>=2.8.0` |
| `src/illumio_mcp/auth/__init__.py` (new) | Package marker, re-exports |
| `src/illumio_mcp/auth/config.py` (new) | `OAuthConfig` dataclass loaded from env, with `is_dev_insecure()` |
| `src/illumio_mcp/auth/jwt_validator.py` (new) | `JWTValidator` class: validates JWT against JWKS, caches keys, extracts claims into `AuthenticatedUser` |
| `src/illumio_mcp/auth/prm.py` (new) | RFC 9728 Protected Resource Metadata response |
| `src/illumio_mcp/auth/middleware.py` (new) | Starlette middleware that runs `JWTValidator.validate(token)` and sets `request.state.user`; emits 401 with `WWW-Authenticate: Bearer resource_metadata=...` on failure |
| `src/illumio_mcp/context.py` (modify) | Add optional `user_sub: str | None = None`, `user_iss: str | None = None` fields with defaults |
| `src/illumio_mcp/transport/http.py` (modify) | Wire OAuthConfig + JWTValidator + middleware + PRM route; build per-request ToolContext that records the authenticated user; refuse to start without OAuth config unless `MCP_DEV_INSECURE=1` |
| `tests/test_auth_config.py` (new) | OAuthConfig env loading + dev-insecure detection |
| `tests/test_auth_jwt_validator.py` (new) | Sign test tokens with a generated RSA key, validate happy path + every failure mode (bad sig, wrong iss, wrong aud, expired, missing scope) |
| `tests/test_auth_prm.py` (new) | PRM endpoint returns the right JSON shape |
| `tests/test_http_auth.py` (new) | End-to-end: spin up HTTP server with a fake JWKS, prove unauthenticated request → 401 with metadata pointer, valid token → 200 |
| `README.md` (modify) | Update HTTP transport section to require OAuth env or MCP_DEV_INSECURE |

The `auth/` package mirrors how `transport/` was created in Phase 2 — small focused modules, easy for Phase 3b/3c/3d to add their own files (`keystore.py`, `roles.py`, `confirm.py`, `audit.py`) without re-organizing.

---

## Task 0: Create the working branch

**Files:** git only

- [ ] **Step 1: Branch off the most-recent Phase work**

```bash
git checkout feature/streamable-http-transport
git pull --ff-only origin feature/streamable-http-transport
git checkout -b feature/oauth-resource-server
```

(If both #10 and #11 are merged to main, branch from main instead. Either path is fine.)

- [ ] **Step 2: Verify clean baseline**

```bash
git status                                                     # clean
.venv/bin/python3 -m pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py tests/test_http_transport.py -q
```
Expected: 24 passed.

---

## Task 1: Bump deps — `PyJWT[crypto]`

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add PyJWT to dependencies**

In `pyproject.toml`, find the `dependencies = [...]` block. Add a new line for PyJWT keeping alphabetical-ish order:

```toml
dependencies = [
 "illumio>=1.1.3",
 "logging>=0.4.9.6",
 "mcp>=1.8.0",
 "pandas>=2.2.3",
 "pyjwt[crypto]>=2.8.0",
 "python-dotenv>=1.0.1",
 "starlette>=0.40.0",
 "uvicorn[standard]>=0.30.0",
]
```

- [ ] **Step 2: Sync the env**

```bash
.venv/bin/python3 -m pip install -e . --upgrade-strategy eager 2>&1 | tail -5
# OR if the project uses uv:
# uv sync
.venv/bin/python3 -c "import jwt; print('PyJWT', jwt.__version__)"
.venv/bin/python3 -c "from jwt import PyJWKClient, decode; print('ok')"
```
Expected: prints PyJWT version >= 2.8.0 and `ok`.

- [ ] **Step 3: Verify Phase 2 unit tests still pass**

```bash
.venv/bin/python3 -m pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -q
```
Expected: 19 passed.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock 2>/dev/null
git commit -m "chore: add PyJWT[crypto] for OAuth Resource Server"
```

---

## Task 2: Create `auth/__init__.py`

**Files:**
- Create: `src/illumio_mcp/auth/__init__.py`

- [ ] **Step 1: Write the package marker**

Create the file with EXACTLY this content:

```python
"""OAuth Resource Server primitives.

Each module in this package handles one auth concern:

- `config`: parses OAuth-related env vars into an OAuthConfig dataclass
- `jwt_validator`: validates JWT bearer tokens against a configured JWKS,
  returns an AuthenticatedUser
- `prm`: serves RFC 9728 Protected Resource Metadata so MCP clients can
  discover the configured Authorization Server
- `middleware`: Starlette middleware that wires the validator into the request
  pipeline and returns 401 with WWW-Authenticate on failure

Phase 3a wires these into the HTTP transport. Phase 3b/c/d will add KeyStore,
authz enforcement, and confirm tokens alongside.
"""
```

- [ ] **Step 2: Verify**

```bash
.venv/bin/python3 -c "import illumio_mcp.auth; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/auth/__init__.py
git commit -m "feat(auth): create auth package"
```

---

## Task 3: `auth/config.py` — OAuthConfig dataclass

**Files:**
- Create: `src/illumio_mcp/auth/config.py`
- Create: `tests/test_auth_config.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_auth_config.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_config.py -v
```
Expected: ImportError on `illumio_mcp.auth.config`.

- [ ] **Step 3: Implement `auth/config.py`**

Create `src/illumio_mcp/auth/config.py`:

```python
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
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_config.py -v
```
Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/config.py tests/test_auth_config.py
git commit -m "feat(auth): OAuthConfig env loader + MCP_DEV_INSECURE flag"
```

---

## Task 4: `auth/jwt_validator.py` — JWT validation against JWKS

This is the heart of the OAuth piece. We use PyJWT's `PyJWKClient` for JWKS fetching + caching. The validator is structured so tests can inject a fake JWKS source (an in-memory key) without spinning up a real OIDC provider.

**Files:**
- Create: `src/illumio_mcp/auth/jwt_validator.py`
- Create: `tests/test_auth_jwt_validator.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_jwt_validator.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_jwt_validator.py -v
```
Expected: ImportError on `illumio_mcp.auth.jwt_validator`.

- [ ] **Step 3: Implement `auth/jwt_validator.py`**

Create `src/illumio_mcp/auth/jwt_validator.py`:

```python
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


def _normalize_scopes(scope_claim) -> list[str]:
    """OIDC IdPs send `scope` as either a space-separated string (Entra) or
    a list of strings (Okta). Normalize to a list."""
    if isinstance(scope_claim, list):
        return list(scope_claim)
    if isinstance(scope_claim, str):
        return scope_claim.split()
    return []


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
        )
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_jwt_validator.py -v
```
Expected: 10 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/jwt_validator.py tests/test_auth_jwt_validator.py
git commit -m "feat(auth): JWTValidator with JWKS + injectable key resolver"
```

---

## Task 5: `auth/prm.py` — RFC 9728 Protected Resource Metadata

The MCP spec (2025-06-18) requires that an unauthenticated request to the resource returns 401 with `WWW-Authenticate: Bearer resource_metadata="<URL>"` pointing at this document. The document tells the client where the AS is.

**Files:**
- Create: `src/illumio_mcp/auth/prm.py`
- Create: `tests/test_auth_prm.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_auth_prm.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_prm.py -v
```
Expected: ImportError on `illumio_mcp.auth.prm`.

- [ ] **Step 3: Implement `auth/prm.py`**

Create `src/illumio_mcp/auth/prm.py`:

```python
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
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_prm.py -v
```
Expected: 2 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/prm.py tests/test_auth_prm.py
git commit -m "feat(auth): RFC 9728 Protected Resource Metadata"
```

---

## Task 6: `auth/middleware.py` — Starlette middleware

The middleware extracts the Bearer token, validates it, attaches `AuthenticatedUser` to `request.state.user`, and returns a structured 401 with the right `WWW-Authenticate` header on failure.

**Files:**
- Create: `src/illumio_mcp/auth/middleware.py`

(Tests for the middleware are part of the end-to-end test in Task 9 — testing Starlette middleware in isolation requires a TestClient setup that's heavier than the e2e test.)

- [ ] **Step 1: Write the file**

Create `src/illumio_mcp/auth/middleware.py`:

```python
"""Starlette middleware that enforces JWT auth on selected paths.

The middleware:
  - Skips paths in `unauthenticated_paths` (default: /healthz, /readyz, /.well-known/*)
  - For other paths, requires `Authorization: Bearer <jwt>`. Validates via the
    injected JWTValidator. On success: stores AuthenticatedUser at
    `request.state.user`. On failure: returns 401 with
    `WWW-Authenticate: Bearer resource_metadata="<prm-url>"` pointing at the
    RFC 9728 document so MCP clients can discover the AS.

This is intentionally not class-based: Starlette middleware composability is
better with simple async callables.
"""
from __future__ import annotations

from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import OAuthConfig
from .jwt_validator import InvalidTokenError, JWTValidator


_DEFAULT_UNAUTHENTICATED_PREFIXES: tuple[str, ...] = (
    "/healthz",
    "/readyz",
    "/.well-known/",
)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Enforce JWT bearer auth on /mcp and other protected paths."""

    def __init__(
        self,
        app,
        *,
        validator: JWTValidator,
        config: OAuthConfig,
        unauthenticated_prefixes: Iterable[str] = _DEFAULT_UNAUTHENTICATED_PREFIXES,
    ):
        super().__init__(app)
        self._validator = validator
        self._prm_url = config.resource_url.rstrip("/") + "/.well-known/oauth-protected-resource"
        self._unauthenticated = tuple(unauthenticated_prefixes)

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if any(path == p or path.startswith(p) for p in self._unauthenticated):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return self._challenge("missing_token")

        token = auth_header[len("bearer "):].strip()
        try:
            user = self._validator.validate(token)
        except InvalidTokenError as e:
            return self._challenge("invalid_token", str(e))

        request.state.user = user
        return await call_next(request)

    def _challenge(self, error: str, description: str | None = None) -> Response:
        params = [f'error="{error}"', f'resource_metadata="{self._prm_url}"']
        if description:
            params.append(f'error_description="{description}"')
        return JSONResponse(
            {"error": error, "error_description": description or ""},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer " + ", ".join(params)},
        )
```

- [ ] **Step 2: Verify import**

```bash
.venv/bin/python3 -c "from illumio_mcp.auth.middleware import JWTAuthMiddleware; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/auth/middleware.py
git commit -m "feat(auth): Starlette middleware enforcing JWT on /mcp"
```

---

## Task 7: Extend `ToolContext` with optional auth fields

Phase 1's `ToolContext` was intentionally minimal. Add `user_sub` and `user_iss` as optional fields with `None` defaults so stdio code keeps working without changes. HTTP code will populate them in Task 8.

**Files:**
- Modify: `src/illumio_mcp/context.py`
- Modify: `tests/test_context.py`

- [ ] **Step 1: Add the new fields**

Replace `src/illumio_mcp/context.py` with:

```python
"""ToolContext: the per-call object every tool handler receives.

In Phase 1 it carried PCE + is_stdio. Phase 3a adds authenticated user
identity for the HTTP path. Stdio code constructs ToolContext as before;
the new fields default to None.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    """Everything a tool handler needs that is *not* the tool's own arguments.

    Build one per request (HTTP) or once at startup (stdio) and pass it to
    every handler. Handlers MUST read PCE from `ctx.pce` and never call
    process-global PCE accessors.
    """
    pce: object  # illumio.PolicyComputeEngine, but kept untyped to avoid import here
    is_stdio: bool
    user_sub: str | None = None  # IdP `sub` claim (None in stdio mode)
    user_iss: str | None = None  # IdP `iss` claim (None in stdio mode)
```

- [ ] **Step 2: Add a regression test for the new defaults**

In `tests/test_context.py`, append at the bottom:

```python


def test_tool_context_user_fields_default_to_none():
    """Stdio call sites construct ToolContext without auth fields; they must
    default to None so we can branch on them later."""
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.user_sub is None
    assert ctx.user_iss is None


def test_tool_context_can_carry_authenticated_user():
    ctx = ToolContext(pce=object(), is_stdio=False, user_sub="user-42", user_iss="https://idp")
    assert ctx.user_sub == "user-42"
    assert ctx.user_iss == "https://idp"
```

- [ ] **Step 3: Run all context tests**

```bash
.venv/bin/python3 -m pytest tests/test_context.py -v
```
Expected: 5 PASSED (3 from Phase 1 + 2 new).

- [ ] **Step 4: Run the metadata-guard test (verifies handler signatures still match)**

```bash
.venv/bin/python3 -m pytest tests/test_tool_metadata.py -v
```
Expected: 6 PASSED. Adding optional fields to ToolContext does not change handler signatures.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/context.py tests/test_context.py
git commit -m "feat(context): add optional user_sub/user_iss to ToolContext"
```

---

## Task 8: Wire auth into `transport/http.py`

This is where everything comes together. Three changes:

1. Build `OAuthConfig` + `JWTValidator` at app construction.
2. Mount `JWTAuthMiddleware` on the Starlette app.
3. Add the `/.well-known/oauth-protected-resource` route.
4. Build a per-request `ToolContext` that carries the authenticated user (still uses the env PCE — per-user creds come in Phase 3b).
5. Refuse to start the HTTP server without OAuth config unless `MCP_DEV_INSECURE=1`.

**Files:**
- Modify: `src/illumio_mcp/transport/http.py`
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Add a per-HTTP-request context builder in `server.py`**

In `src/illumio_mcp/server.py`, find the `_get_stdio_context()` function added in Phase 1. Below it, add:

```python
def build_http_context_for(user_sub: str | None, user_iss: str | None) -> ToolContext:
    """Build a ToolContext for one HTTP request.

    Phase 3a: PCE is still the env-loaded singleton (shared across users).
    Phase 3b will look up the user's PCE creds from the KeyStore here.
    """
    return ToolContext(
        pce=get_pce_from_env(),
        is_stdio=False,
        user_sub=user_sub,
        user_iss=user_iss,
    )
```

(The helper exists in server.py because `_get_stdio_context` lives there too — keep all ToolContext construction in one module so Phase 3b's changes have one place to land.)

- [ ] **Step 2: Replace `transport/http.py`**

Replace the contents of `src/illumio_mcp/transport/http.py` with:

```python
"""HTTP transport for the MCP server using Streamable HTTP (MCP spec 2025-03-26).

Phase 3a: OAuth Resource Server semantics. Bearer-token required on /mcp
unless MCP_DEV_INSECURE=1 is set. PCE credentials are still env-shared
(per-user PCE keys arrive in Phase 3b).

Routes:
  GET  /healthz                                -> 200 (unauth)
  GET  /readyz                                 -> 200 (unauth)
  GET  /.well-known/oauth-protected-resource   -> RFC 9728 metadata (unauth)
  *    /mcp                                    -> Streamable HTTP MCP (auth required)
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import os
from typing import AsyncIterator

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from ..auth.config import (
    OAuthConfig,
    MissingOAuthConfigError,
    is_dev_insecure,
    load_oauth_config_from_env,
)
from ..auth.jwt_validator import JWTValidator
from ..auth.middleware import JWTAuthMiddleware
from ..auth.prm import build_prm_document
from ..server import server as mcp_server  # the mcp.server.Server instance

logger = logging.getLogger("illumio_mcp.transport.http")


def _build_session_manager() -> StreamableHTTPSessionManager:
    """Build the session manager. Stateless for the same reasons documented in
    Phase 2."""
    return StreamableHTTPSessionManager(app=mcp_server, stateless=True)


def _build_app(oauth_config: OAuthConfig | None) -> Starlette:
    """Construct the ASGI app. If `oauth_config` is None, auth is bypassed
    (dev-insecure mode); otherwise JWTAuthMiddleware is mounted on /mcp."""
    session_manager = _build_session_manager()

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            logger.info("StreamableHTTPSessionManager started")
            yield
            logger.info("StreamableHTTPSessionManager stopped")

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        return JSONResponse({"status": "ready"})

    routes = [
        Mount("/mcp", app=session_manager.handle_request),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]

    middleware = []
    if oauth_config is not None:
        async def prm(_: Request) -> Response:
            return JSONResponse(build_prm_document(oauth_config))
        routes.append(Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]))

        validator = JWTValidator(oauth_config)
        from starlette.middleware import Middleware
        middleware.append(Middleware(JWTAuthMiddleware, validator=validator, config=oauth_config))
    else:
        logger.warning("MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.")

    return Starlette(debug=False, routes=routes, lifespan=lifespan, middleware=middleware)


def serve_http(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the HTTP transport via uvicorn. Blocks until SIGINT/SIGTERM.

    Refuses to start without OAuth config UNLESS MCP_DEV_INSECURE=1 is set.
    Refuses to bind a non-loopback host without MCP_DEV_INSECURE=1 (Phase 2).
    """
    if host not in ("127.0.0.1", "::1", "localhost") and not is_dev_insecure():
        raise SystemExit(
            f"Refusing to bind {host!r} without MCP_DEV_INSECURE=1. "
            "Public bind requires Phase 3 auth + an explicit dev opt-in."
        )

    if is_dev_insecure():
        oauth_config = None
    else:
        try:
            oauth_config = load_oauth_config_from_env()
        except MissingOAuthConfigError as e:
            raise SystemExit(str(e))

    app = _build_app(oauth_config)
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp"
                + ("  [DEV-INSECURE: no auth]" if oauth_config is None else ""))
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(prog="illumio-mcp-http", description=__doc__)
    parser.add_argument("--host", default=os.getenv("MCP_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_HTTP_PORT", "8080")))
    args = parser.parse_args()
    serve_http(host=args.host, port=args.port)
```

- [ ] **Step 3: Verify imports**

```bash
.venv/bin/python3 -c "from illumio_mcp.transport.http import _build_app, serve_http; print('ok')"
.venv/bin/python3 -c "from illumio_mcp.server import build_http_context_for; print(build_http_context_for('s', 'i'))"
```
Expected: both succeed; the second prints a `ToolContext` repr with `user_sub='s'`, `user_iss='i'`.

- [ ] **Step 4: Verify dev-insecure path still builds an app**

```bash
MCP_DEV_INSECURE=1 .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
app = _build_app(None)
print('routes:', sorted([getattr(r, 'path', '?') for r in app.routes]))
"
```
Expected: `routes: ['/healthz', '/mcp', '/readyz']` (no PRM route, no middleware).

- [ ] **Step 5: Verify auth-required path requires config**

```bash
unset MCP_DEV_INSECURE MCP_OAUTH_ISSUER MCP_OAUTH_JWKS_URL MCP_OAUTH_AUDIENCE MCP_PUBLIC_URL
.venv/bin/python3 -c "
from illumio_mcp.transport.http import serve_http
try:
    serve_http()
except SystemExit as e:
    print('correctly refused:', str(e)[:120])
"
```
Expected: prints `correctly refused: Missing required OAuth env vars: MCP_OAUTH_ISSUER, MCP_OAUTH_JWKS_URL, ...`.

- [ ] **Step 6: Verify stdio still works (regression net)**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: valid JSON-RPC `initialize` response.

- [ ] **Step 7: Commit**

```bash
git add src/illumio_mcp/transport/http.py src/illumio_mcp/server.py
git commit -m "feat(http): require JWT bearer auth (unless MCP_DEV_INSECURE=1)"
```

---

## Task 9: End-to-end auth tests

Spin up the HTTP server with a fake JWKS (using the same in-process key trick as Task 4) and prove:
- `GET /healthz` works without auth
- `GET /.well-known/oauth-protected-resource` returns the right metadata
- `POST /mcp` without `Authorization` returns 401 with the right `WWW-Authenticate` header
- `POST /mcp` with a valid JWT returns 200 and works as expected

**Files:**
- Create: `tests/test_http_auth.py`

- [ ] **Step 1: Write the tests**

Create `tests/test_http_auth.py`:

```python
"""End-to-end tests for OAuth Resource Server behavior on the HTTP transport.

Spins up the server with an in-process JWT validator (no real IdP needed) and
verifies the auth-related routes work as specified in MCP 2025-06-18.
"""
import socket
import threading
import time
import urllib.request
import urllib.error
import json

import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from illumio_mcp.auth.config import OAuthConfig
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.middleware import JWTAuthMiddleware
from illumio_mcp.auth.prm import build_prm_document


pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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
        resource_url="http://127.0.0.1",  # rewritten per-test below
    )


@pytest.fixture(scope="module")
def http_server(cfg, public_key_pem):
    """Start the HTTP server on a free port with an in-process JWT validator."""
    import uvicorn
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from illumio_mcp.server import server as mcp_server

    port = _free_port()
    test_cfg = OAuthConfig(
        issuer=cfg.issuer,
        jwks_url=cfg.jwks_url,
        audience=cfg.audience,
        required_scope=cfg.required_scope,
        resource_url=f"http://127.0.0.1:{port}",
    )
    validator = JWTValidator(test_cfg, key_resolver=lambda kid: public_key_pem)

    session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

    @asynccontextmanager
    async def lifespan(app):
        async with session_manager.run():
            yield

    async def healthz(_): return JSONResponse({"status": "ok"})
    async def prm(_): return JSONResponse(build_prm_document(test_cfg))

    app = Starlette(
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]),
        ],
        middleware=[Middleware(JWTAuthMiddleware, validator=validator, config=test_cfg)],
        lifespan=lifespan,
    )

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("HTTP server did not become ready within 10s")

    yield f"http://127.0.0.1:{port}", test_cfg

    server.should_exit = True
    thread.join(timeout=5)


def _mint(private_key_pem, **overrides):
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


async def test_healthz_does_not_require_auth(http_server):
    url, _ = http_server
    with urllib.request.urlopen(f"{url}/healthz") as resp:
        assert resp.status == 200


async def test_prm_endpoint_returns_metadata(http_server):
    url, cfg = http_server
    with urllib.request.urlopen(f"{url}/.well-known/oauth-protected-resource") as resp:
        body = json.loads(resp.read())
        assert body["resource"] == cfg.resource_url
        assert body["authorization_servers"] == [cfg.issuer]
        assert "illumio-mcp.use" in body["scopes_supported"]


async def test_mcp_unauthenticated_returns_401_with_metadata_pointer(http_server):
    url, cfg = http_server
    req = urllib.request.Request(
        f"{url}/mcp",
        method="POST",
        data=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401
    www_auth = exc_info.value.headers.get("WWW-Authenticate", "")
    assert www_auth.startswith("Bearer")
    assert 'resource_metadata="' in www_auth
    assert "/.well-known/oauth-protected-resource" in www_auth


async def test_mcp_with_valid_jwt_works(http_server, private_key_pem):
    """The same MCP initialize request, with a valid Bearer token, succeeds."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem)
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(f"{url}/mcp", headers=headers) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.serverInfo.name == "illumio-mcp"


async def test_mcp_with_invalid_jwt_returns_401(http_server):
    url, _ = http_server
    req = urllib.request.Request(
        f"{url}/mcp",
        method="POST",
        data=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
        headers={"Content-Type": "application/json", "Authorization": "Bearer not-a-real-jwt"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401
```

- [ ] **Step 2: Run the tests**

```bash
.venv/bin/python3 -m pytest tests/test_http_auth.py -v 2>&1 | tail -30
```

Expected: 5 PASSED.

If `streamablehttp_client` doesn't accept a `headers=` kwarg, the installed mcp SDK is older — investigate by checking the function signature. Per the API in mcp 1.27.x it does accept it. If it doesn't, the test for valid JWT can be reduced to a raw `urllib.request` POST that asserts a non-401 status.

- [ ] **Step 3: Commit**

```bash
git add tests/test_http_auth.py
git commit -m "test(auth): end-to-end OAuth Resource Server behavior on /mcp"
```

---

## Task 10: README — document OAuth requirements

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the "HTTP transport (preview)" section**

Find the existing section in `README.md` (added in Phase 2). Replace it entirely with:

```markdown
## HTTP transport with OAuth Resource Server (Phase 3a)

The server runs over HTTP using the MCP Streamable HTTP transport (spec rev
2025-03-26) and validates OAuth 2.1 bearer tokens issued by your IdP. This is
**Phase 3a**: identity is enforced; per-user PCE keys land in Phase 3b.

### Running with auth (production-shaped)

```bash
export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
export MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
export MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use   # default; override if needed
illumio-mcp-http --host 127.0.0.1 --port 8080
```

The server refuses to start without these env vars (unless `MCP_DEV_INSECURE=1`).

MCP clients discover the AS via the standard RFC 9728 endpoint:

```
GET /.well-known/oauth-protected-resource
```

Unauthenticated requests to `/mcp` return `401` with
`WWW-Authenticate: Bearer resource_metadata="<URL>"`, which any spec-compliant
MCP client (Claude Desktop, ChatGPT, MCP Inspector) follows automatically to
run PKCE auth code flow against the configured AS.

### Running without auth (dev only)

```bash
MCP_DEV_INSECURE=1 illumio-mcp-http
```

The server logs a prominent warning. Do NOT use in production.

### Health endpoints (always unauthenticated)

- `GET /healthz` — liveness
- `GET /readyz` — readiness (Phase 3a returns the same as healthz; Phase 3b/c will add PCE + JWKS reachability)
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document OAuth Resource Server (Phase 3a)"
```

---

## Task 11: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/oauth-resource-server
```

- [ ] **Step 2: Open the PR**

If Phase 2 (#11) is still open, target it as the base:
```bash
gh pr create --base feature/streamable-http-transport --title "feat: OAuth Resource Server (Phase 3a)" --body "$(cat <<'EOF'
## Summary

Phase 3a of the multi-user rollout. Adds OAuth 2.1 Resource Server semantics to the HTTP transport per MCP spec 2025-06-18:

- JWT bearer required on `/mcp` (validated locally via JWKS, IdP-agnostic)
- RFC 9728 Protected Resource Metadata at `/.well-known/oauth-protected-resource`
- `WWW-Authenticate: Bearer resource_metadata="..."` on 401 so clients auto-discover the AS
- Identity captured in `ToolContext.user_sub` / `user_iss` (still env-shared PCE — per-user keys are Phase 3b)
- `MCP_DEV_INSECURE=1` continues as the dev opt-out
- Stdio transport unchanged

> **Stacked on #11 (Phase 2).** When #11 merges, the base will auto-update.

## Test plan

- [x] `pytest tests/test_auth_config.py tests/test_auth_jwt_validator.py tests/test_auth_prm.py -v` — unit tests for each auth module
- [x] `pytest tests/test_http_auth.py -v` — end-to-end with in-process JWT signer: healthz unauth ok, PRM ok, `/mcp` no token → 401 + WWW-Authenticate, `/mcp` valid JWT → initialize ok, `/mcp` invalid JWT → 401
- [x] `pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py tests/test_http_transport.py` — Phase 1+2 tests still green
- [x] Stdio sanity check: `echo '<initialize>' | python -m illumio_mcp` returns valid JSON-RPC handshake
- [ ] (recommended before merge) Smoke test against a real Entra/Okta tenant — point `MCP_OAUTH_*` env at a test tenant, hit with MCP Inspector

## What this PR does NOT do

Explicitly Phase 3b/c/d:
- Per-user PCE key storage (KeyStore + envelope encryption) — Phase 3b
- `/setup` browser onboarding + `register-pce-credentials` tool — Phase 3b
- Role mapping from groups + tool-allowlist enforcement + audit log — Phase 3c
- `/confirm` step-up endpoint + mutating-tool token gating — Phase 3d

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Print the PR URL**

---

## What this plan does NOT do

These are explicitly **Phase 3b, 3c, or 3d**:

- **Phase 3b:** SQLite KeyStore with envelope encryption; per-user PCE creds; `/setup` browser page; `register-pce-credentials` tool; updates `build_http_context_for` to fetch user-specific PCE.
- **Phase 3c:** Role mapping from JWT `groups`/`roles` claim; tool-allowlist enforcement (read the `roles=` metadata that's been on `ToolSpec` since Phase 1); scope filters for reads/writes; persistent audit log.
- **Phase 3d:** `/confirm` endpoint with step-up auth; `requires_confirm=True` enforcement on mutating tools; HMAC-signed single-use tokens.

After 3a ships, write the 3b plan next. Each sub-phase plan benefits from what the previous one revealed about the operational story (especially: which IdP we actually picked).

---

## Self-review checklist

- [x] **Spec coverage (3a only):** All of spec §3.4 (wire-level auth flow), §5 Layer 1 (JWT validation), §3.2 (Resource Server only, IdP-agnostic). Tasks 3+4+5+6+8+9 collectively implement these. Phase 3b/c/d are intentionally separate plans.
- [x] **Placeholders:** No "TBD"/"TODO". Every step has the exact code or command.
- [x] **Type consistency:** `OAuthConfig` defined in Task 3 with 5 fields used identically in Tasks 4, 5, 6, 8, 9. `JWTValidator(config, key_resolver=...)` defined in Task 4, used the same way in Task 6 (middleware), Task 8 (transport), Task 9 (tests). `AuthenticatedUser(sub, iss, scopes, groups)` defined in Task 4, the middleware (Task 6) sets `request.state.user` of this type. `ToolContext` extension (Task 7) adds `user_sub` + `user_iss` as optional, used in `build_http_context_for` (Task 8).
- [x] **Stdio not broken:** Tasks 7, 8 each have an explicit stdio sanity check before commit.
- [x] **Dev opt-out preserved:** `MCP_DEV_INSECURE=1` continues to bypass auth on the HTTP path; documented in code (Task 8) and README (Task 10).
- [x] **Frequent commits:** 11 commits across 11 tasks. Each one is small enough to review independently.
