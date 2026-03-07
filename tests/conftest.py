import pytest
import os
import dotenv
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


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
