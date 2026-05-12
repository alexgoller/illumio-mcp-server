"""Credential-management tools — let an authenticated user register, inspect,
and delete the PCE credentials this server uses on their behalf.

These tools do NOT need a PCE client (`requires_pce=False`). They are the
escape hatch that lets a freshly-onboarded user finish bootstrap without
leaving the MCP client.
"""
import json
import logging
from typing import Any

import mcp.types as types

from ..pce import PCECredentials

logger = logging.getLogger("illumio_mcp")


def _err(message: str) -> list:
    return [types.TextContent(type="text", text=json.dumps({"error": message}))]


def _identity(ctx) -> tuple[str, str] | None:
    """Return (sub, iss) if both present in ctx; otherwise None."""
    if ctx.user_sub and ctx.user_iss:
        return ctx.user_sub, ctx.user_iss
    return None


def handle_register_pce_credentials(ctx, arguments: dict) -> list:
    """Store (or overwrite) the PCE credentials for the current authenticated user."""
    if getattr(ctx, "pce_mode", "per_user") == "shared":
        return _err(
            "Server is running in shared-PCE-key mode; per-user PCE credentials "
            "are not used. Contact your operator to switch to per_user mode if you "
            "need to register your own PCE key."
        )
    if ctx.keystore is None:
        return _err("Keystore not available — server not running in HTTP mode with auth enabled.")
    ident = _identity(ctx)
    if ident is None:
        return _err("Cannot register credentials in stdio mode (no user identity).")
    sub, iss = ident

    try:
        creds = PCECredentials(
            host=str(arguments["pce_host"]),
            port=int(arguments["pce_port"]),
            org_id=int(arguments["pce_org_id"]),
            api_key=str(arguments["api_key"]),
            api_secret=str(arguments["api_secret"]),
            tls_verify=bool(arguments.get("tls_verify", True)),
        )
    except (KeyError, ValueError, TypeError) as e:
        return _err(f"Invalid arguments: {e}")

    label = arguments.get("label")
    ctx.keystore.put(sub=sub, iss=iss, creds=creds, label=label)
    logger.info("Registered PCE credentials for sub=%s iss=%s", sub, iss)
    return [types.TextContent(type="text", text=json.dumps({
        "status": "ok",
        "message": f"PCE credentials registered for {sub}.",
        "pce_host": creds.host,
        "pce_org_id": creds.org_id,
        "label": label,
    }, indent=2))]


def handle_delete_pce_credentials(ctx, arguments: dict) -> list:
    """Remove the current user's PCE credentials. Idempotent."""
    if getattr(ctx, "pce_mode", "per_user") == "shared":
        return _err(
            "Server is running in shared-PCE-key mode; per-user PCE credentials "
            "are not used. Contact your operator to switch to per_user mode if you "
            "need to register your own PCE key."
        )
    if ctx.keystore is None:
        return _err("Keystore not available.")
    ident = _identity(ctx)
    if ident is None:
        return _err("Cannot delete credentials in stdio mode (no user identity).")
    sub, iss = ident
    deleted = ctx.keystore.delete(sub=sub, iss=iss)
    return [types.TextContent(type="text", text=json.dumps({
        "status": "ok" if deleted else "noop",
        "message": (
            f"Deleted PCE credentials for {sub}." if deleted
            else "No credentials were registered for this user."
        ),
    }))]


def handle_check_pce_credentials_status(ctx, arguments: dict) -> list:
    """Tell the caller whether credentials are registered (without revealing them)."""
    if getattr(ctx, "pce_mode", "per_user") == "shared":
        return [types.TextContent(type="text", text=json.dumps({
            "registered": True,
            "mode": "shared",
            "message": "Server is in shared-PCE-key mode; the operator-configured PCE service account is used.",
        }))]
    if ctx.keystore is None:
        return _err("Keystore not available.")
    ident = _identity(ctx)
    if ident is None:
        return [types.TextContent(type="text", text=json.dumps({
            "registered": True,
            "mode": "stdio",
            "message": "stdio mode uses env-loaded PCE credentials; per-user registration is HTTP-only.",
        }))]
    sub, iss = ident
    creds = ctx.keystore.get(sub=sub, iss=iss)
    if creds is None:
        return [types.TextContent(type="text", text=json.dumps({"registered": False}))]
    return [types.TextContent(type="text", text=json.dumps({
        "registered": True,
        "pce_host": creds.host,
        "pce_port": creds.port,
        "pce_org_id": creds.org_id,
        "tls_verify": creds.tls_verify,
    }))]
