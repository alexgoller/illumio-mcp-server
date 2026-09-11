---
title: Testing
layout: default
parent: Development
---

{: .note }
> **CI.** `.github/workflows/ci.yml` runs the suite on Python 3.12 and 3.13 for every
> push to `main` and every pull request. CI has no PCE, so PCE-dependent tests skip via
> the `requires_pce` fixture while the rest run — roughly 172 tests. The job fails if
> fewer than 150 pass, so a regression in the PCE gating cannot turn the suite into a
> silently empty green run. Two further jobs check that `docs/tools.md` still matches the
> tool registry and that no dependency carries a known OSV advisory.

# Testing

Three tiers of tests. Most work without a real PCE.

---

## Tier 1: Fast unit tests (no PCE required)

These test authentication, authorization, crypto, and registry correctness. They run in under 10 seconds with no external dependencies.

```bash
.venv/bin/python3 -m pytest \
  tests/test_auth_config.py \
  tests/test_auth_jwt_validator.py \
  tests/test_auth_prm.py \
  tests/test_auth_crypto.py \
  tests/test_auth_keystore.py \
  tests/test_auth_roles.py \
  tests/test_auth_audit.py \
  tests/test_auth_confirm.py \
  tests/test_auth_confirm_replay.py \
  tests/test_auth_pce_mode.py \
  tests/test_context.py \
  tests/test_registry.py \
  tests/test_pce_builder.py \
  tests/test_tool_metadata.py \
  tests/test_credentials_tools.py \
  -v
```

### What each test file covers

| File | Coverage |
|---|---|
| `test_auth_config.py` | `OAuthConfig` env loading, `is_dev_insecure()`, `MissingOAuthConfigError` |
| `test_auth_jwt_validator.py` | Happy path + all 6 failure modes (bad sig, wrong iss, wrong aud, expired, missing scope, garbage) |
| `test_auth_prm.py` | RFC 9728 PRM document shape |
| `test_auth_crypto.py` | `EnvelopeCipher` round-trip, AAD binding, tamper detection |
| `test_auth_keystore.py` | `SQLiteKeyStore` CRUD, upsert, delete, missing-row handling |
| `test_auth_roles.py` | Group→role mapping, highest-role-wins, default_role fallback |
| `test_auth_audit.py` | `SQLiteAuditLog` writes, `NullAuditLog` no-ops |
| `test_auth_confirm.py` | `ConfirmTokenManager` mint/verify, all failure modes |
| `test_auth_confirm_replay.py` | `SQLiteJtiStore` mark-used, replay rejection |
| `test_auth_pce_mode.py` | `load_pce_mode_from_env()`, defaults, invalid values |
| `test_context.py` | `ToolContext` dataclass fields, defaults |
| `test_registry.py` | `ToolSpec` validation, role constants |
| `test_pce_builder.py` | `build_pce_for()` returns fresh instances, `get_pce_from_env()` caches |
| `test_tool_metadata.py` | Guard tests: every tool has roles, `ctx`-first arg, mutating flag, count |
| `test_credentials_tools.py` | `register-pce-credentials`, `delete-pce-credentials`, `check-pce-credentials-status` with a fake keystore |

---

## Tier 2: HTTP transport tests (in-process JWT signer, no real PCE)

These spin up the full Starlette app in a background thread on a free local port, issue real HTTP requests, and exercise the auth middleware and session manager end-to-end. They use an in-process RSA key to sign test JWTs — no real IdP is needed.

```bash
.venv/bin/python3 -m pytest \
  tests/test_http_transport.py \
  tests/test_http_auth.py \
  tests/test_http_authz.py \
  tests/test_http_per_user.py \
  tests/test_http_confirm.py \
  tests/test_http_shared_mode.py \
  -v
```

### Key patterns used in these tests

**In-process JWT signing**

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt as pyjwt

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_key_pem = rsa_key.private_bytes(...)
public_key_pem = rsa_key.public_key().public_bytes(...)

# Build a validator that uses the in-process key directly
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.config import OAuthConfig

validator = JWTValidator(cfg, key_resolver=lambda kid: public_key_pem)

# Mint a test token
token = pyjwt.encode(
    {"iss": cfg.issuer, "aud": cfg.audience, "sub": "test-user",
     "exp": int(time.time()) + 600, "iat": int(time.time()),
     "scope": "illumio-mcp.use", "groups": ["sg-test-admin"]},
    private_key_pem, algorithm="RS256", headers={"kid": "test-kid"}
)
```

**Stubbing `build_pce_for` and `get_pce_from_env`**

Tests that need to bypass a real PCE monkeypatch the builder:

```python
import illumio_mcp.pce as pce_mod

class FakePCE:
    """Minimal PCE stub that returns empty lists for all queries."""
    class _services:
        @staticmethod
        def get(**kwargs): return []
    # ... add stubs as needed

monkeypatch.setattr(pce_mod, "build_pce_for", lambda creds: FakePCE())
monkeypatch.setattr(pce_mod, "get_pce_from_env", lambda: FakePCE())
```

**SQLite test databases with `tmp_path_factory`**

```python
@pytest.fixture(scope="module")
def keystore(tmp_path_factory):
    from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek
    from illumio_mcp.auth.keystore import SQLiteKeyStore
    db_path = str(tmp_path_factory.mktemp("keystore") / "keys.db")
    return SQLiteKeyStore(db_path=db_path, cipher=EnvelopeCipher(generate_kek()))
```

**Streamable HTTP server fixture (free port + uvicorn thread)**

```python
@pytest.fixture(scope="module")
def http_server_url(... other fixtures ...):
    import uvicorn
    from illumio_mcp.transport.http import _build_app
    port = _free_port()
    config = uvicorn.Config(_build_app(...), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait for /healthz to respond
    ...
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)
```

---

## Tier 3: Full integration tests against a real PCE

These tests exercise the full tool handler logic against a real PCE instance. They require a `.env` file with valid PCE credentials.

```bash
# Create .env
cat > .env <<EOF
PCE_HOST=https://your-pce.example.com
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=your-api-key
API_SECRET=your-api-secret
EOF

# Run integration tests
.venv/bin/python3 -m pytest tests/test_mcp_tools.py -v
```

These tests create and clean up real PCE objects (workloads, labels, rulesets). Run against a lab PCE, not production.

To run the PCE-free tiers from CI while skipping the PCE tests:

```bash
# PCE-dependent tests skip automatically when no PCE is reachable.
.venv/bin/python3 -m pytest tests/ -q
```

---

## Running all tiers at once

```bash
# With PCE configured in .env
.venv/bin/python3 -m pytest tests/ -v

# Without PCE: the requires_pce fixture skips PCE-dependent tests with a reason.
.venv/bin/python3 -m pytest tests/ -q
```

Expected CI output (no PCE):

```
... passed, 0 failed
```
