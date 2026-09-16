"""Tools describing the server itself. No PCE required.

`get-server-changelog` exists for a failure mode specific to long-running MCP
sessions: the client caches `tools/list` at connect time, and the model forms
assumptions about tool behaviour from responses it has already seen. Update the
server underneath a live session and neither refreshes. The session keeps
calling tools the old way and gets different answers without anything
announcing that the contract moved.
"""
import json
import logging

import mcp.types as types

from ..changelog import load_releases, releases_since, unlearn_items

logger = logging.getLogger('illumio_mcp')


def _distribution_version() -> str | None:
    """Version recorded in the installed distribution metadata, if any.

    Deliberately not the primary answer: in an editable install this is
    whatever `pip install -e` last wrote, so it goes stale the moment the
    source tree moves ahead. Reporting it as the server version would tell a
    session it is talking to 0.1.0 while running 0.3.0 code.
    """
    try:
        from importlib.metadata import version
        return version("illumio-mcp")
    except Exception:  # not installed as a distribution (source checkout)
        return None


def handle_get_server_changelog(ctx, arguments: dict) -> list:
    """Report what changed in this server, optionally since a given version."""
    arguments = arguments or {}
    try:
        releases = load_releases()
        if not releases:
            return [types.TextContent(type="text", text=json.dumps({
                "server_version": _distribution_version() or "unknown",
                "releases": [],
                "note": "CHANGELOG.md was not found alongside this install.",
            }))]

        since = arguments.get("since")
        selected = releases_since(releases, since)
        include_unlearn = arguments.get("unlearn_only", False)

        # CHANGELOG.md ships with the code, so its newest entry describes what
        # is actually running -- unlike distribution metadata, which an
        # editable install leaves behind.
        code_version = releases[0]["version"]
        dist_version = _distribution_version()

        payload = {
            "server_version": code_version,
            "latest_release": code_version,
            "queried_since": since,
            # Surfaced first and separately: a changed contract makes a session
            # confidently wrong, where a missing feature merely fails loudly.
            "unlearn": unlearn_items(selected),
        }

        if not include_unlearn:
            payload["releases"] = [
                {"version": r["version"], "date": r["date"], "sections": r["sections"]}
                for r in selected
            ]

        if dist_version and dist_version != code_version:
            payload["distribution_version"] = dist_version
            payload["version_note"] = (
                f"Installed distribution metadata says {dist_version} but the "
                f"shipped changelog says {code_version}; this is normally an "
                f"editable install whose metadata was not rewritten. The "
                f"changelog reflects the running code."
            )

        if since and not selected:
            payload["note"] = (
                f"Nothing newer than {since}. This server is at "
                f"{releases[0]['version']}."
            )
        elif payload["unlearn"]:
            payload["note"] = (
                f"{len(payload['unlearn'])} behaviour change(s) may invalidate "
                f"assumptions formed earlier in this session. Read `unlearn` "
                f"before relying on cached expectations about these tools."
            )

        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]
    except Exception as e:
        logger.error("Failed to read changelog: %s", e, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({
            "error": "changelog_unavailable", "message": str(e)}))]
