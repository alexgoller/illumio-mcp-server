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


@pytest.fixture(scope="module", autouse=True)
def reset_sse_app_status():
    """Unbind sse-starlette's process-global shutdown Event between test modules.

    `sse_starlette.sse.AppStatus.should_exit_event` is a class attribute created
    lazily on first use (sse.py:187-188) and then awaited (sse.py:194) from
    whatever event loop is current. Each HTTP test module starts uvicorn in a new
    thread with a new event loop, so the second module inherits an Event bound to
    the first module's loop and `.wait()` raises

        RuntimeError: <asyncio.locks.Event ...> is bound to a different event loop

    That kills the SSE response task, the server never finishes the response, and
    the client blocks forever. Plain HTTP routes such as /healthz are unaffected,
    which is why only the /mcp endpoint hung.

    Resetting per module -- rather than per test -- keeps the Event stable for the
    lifetime of each module's server while guaranteeing a fresh one whenever a new
    loop takes over.
    """
    from sse_starlette.sse import AppStatus
    AppStatus.should_exit_event = None
    AppStatus.should_exit = False
    yield


@pytest.fixture(scope="module", autouse=True)
def restore_pce_module_state():
    """Undo module-level monkeypatching of illumio_mcp.pce between test modules.

    Four HTTP test modules stub `build_pce_for` (and one also `get_pce_from_env`)
    so they need no real PCE, and they do restore those functions. But
    `get_pce_from_env` memoises its result in the module global
    `_stdio_singleton` (pce.py:58-77), and nothing resets it. A FakePCE built
    while a stub was active therefore survives the restore and leaks into every
    later module as

        Error: Failed in PCE operation: 'FakePCE' object has no attribute 'check_connection'

    Snapshotting all three and restoring them on teardown fixes the whole class,
    rather than patching each module's teardown one at a time.
    """
    from illumio_mcp import pce as pce_mod
    saved_build = pce_mod.build_pce_for
    saved_from_env = pce_mod.get_pce_from_env
    saved_singleton = pce_mod._stdio_singleton
    yield
    pce_mod.build_pce_for = saved_build
    pce_mod.get_pce_from_env = saved_from_env
    pce_mod._stdio_singleton = saved_singleton


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
