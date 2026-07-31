import pytest
import os
import dotenv
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from illumio import PolicyComputeEngine, Label

dotenv.load_dotenv()


def get_server_params():
    """MCP server startup parameters."""
    venv_python = os.path.join(
        os.path.dirname(__file__), "..", ".venv", "bin", "python3"
    )
    env = {
        **os.environ,
        "PCE_HOST": os.getenv("PCE_HOST", ""),
        "PCE_PORT": os.getenv("PCE_PORT", ""),
        "PCE_ORG_ID": os.getenv("PCE_ORG_ID", ""),
        "API_KEY": os.getenv("API_KEY", ""),
        "API_SECRET": os.getenv("API_SECRET", ""),
    }
    return StdioServerParameters(
        command=venv_python,
        args=["-m", "illumio_mcp"],
        env=env,
    )


def get_pce() -> PolicyComputeEngine:
    pce = PolicyComputeEngine(
        os.getenv("PCE_HOST"),
        port=os.getenv("PCE_PORT"),
        org_id=os.getenv("PCE_ORG_ID"),
    )
    pce.set_credentials(os.getenv("API_KEY"), os.getenv("API_SECRET"))
    pce._session.verify = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")
    return pce


@pytest.fixture(scope="session")
def pce_unavailable_reason() -> str | None:
    """Probe the PCE once per session. Returns why it is unusable, or None if fine.

    Most of this suite -- the auth, registry, crypto, and HTTP-transport tests --
    never touches a PCE. Probing here rather than letting an autouse fixture raise
    keeps an absent or expired PCE credential from taking the whole suite down
    with it, which is how a stale tool-list assertion once went unnoticed.
    """
    missing = [v for v in ("PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "API_KEY", "API_SECRET")
               if not os.getenv(v)]
    if missing:
        return f"PCE env vars not set: {', '.join(missing)}"
    try:
        get_pce().labels.get(params={"key": "app", "value": "pos"})
    except Exception as e:
        return f"PCE unreachable: {e}"
    return None


@pytest.fixture(scope="session", autouse=True)
def ensure_pos_label(pce_unavailable_reason):
    """Ensure the app=pos label exists on the PCE before any tests run.

    Autouse, but a deliberate no-op when the PCE is unusable. Tests that genuinely
    need a PCE opt in via `requires_pce` and skip with a clear reason; everything
    else runs regardless.
    """
    if pce_unavailable_reason is None:
        pce = get_pce()
        if not pce.labels.get(params={"key": "app", "value": "pos"}):
            pce.labels.create(Label(key="app", value="pos"))
    yield


@pytest.fixture
def requires_pce(pce_unavailable_reason):
    """Skip a test that cannot run without a reachable PCE."""
    if pce_unavailable_reason is not None:
        pytest.skip(pce_unavailable_reason)
