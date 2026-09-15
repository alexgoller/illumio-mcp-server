"""Parse CHANGELOG.md so a live MCP session can ask what changed.

The problem this solves is specific to long-running sessions. A client caches
`tools/list` at connect time and forms assumptions about tool behaviour from the
responses it has seen. Update the server underneath it and neither is refreshed:
the session keeps calling tools the old way and silently gets different answers.
A new tool is at least discoverable on reconnect; a *changed contract* is not.

CHANGELOG.md is the single source. Parsing it rather than duplicating the
entries into Python avoids a second place to forget -- the same failure mode
that let the advertised tool list drift from TOOL_REGISTRY.
"""
from __future__ import annotations

import logging
import pathlib
import re

logger = logging.getLogger(__name__)

# Repo root in a source checkout; alongside the package in an installed wheel.
_CANDIDATES = [
    pathlib.Path(__file__).resolve().parents[2] / "CHANGELOG.md",
    pathlib.Path(__file__).resolve().parent / "data" / "CHANGELOG.md",
]

_VERSION_HEADING = re.compile(r"^##\s*\[?([0-9]+\.[0-9]+\.[0-9]+|[Uu]nreleased)\]?\s*(?:[—–-]\s*(.+))?$")
_SECTION_HEADING = re.compile(r"^###\s+(.+?)\s*$")


def changelog_path() -> pathlib.Path | None:
    for candidate in _CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def _version_key(version: str) -> tuple:
    """Sortable key. 'unreleased' sorts above every released version.

    Short forms are padded to three components, so "1.2" means 1.2.0 rather
    than sorting as a 2-tuple -- (1, 2) compares as LOWER than (1, 2, 0), which
    would have made `since="1.2"` filter out 1.2.x releases it should include.
    Raises ValueError on anything non-numeric so callers can fall back.
    """
    if version.lower() == "unreleased":
        return (float("inf"),)
    parts = [int(p) for p in version.split(".")]
    if not parts or len(parts) > 3:
        raise ValueError(f"not a version: {version!r}")
    return tuple(parts + [0] * (3 - len(parts)))


def parse_changelog(text: str) -> list[dict]:
    """Split the file into per-release records.

    Returns newest-first, each: {version, date, sections: {name: [items]}}.
    """
    releases: list[dict] = []
    current: dict | None = None
    section: str | None = None
    buffer: list[str] = []

    def flush_item():
        if current is not None and section and buffer:
            text_item = " ".join(" ".join(buffer).split())
            if text_item:
                current["sections"].setdefault(section, []).append(text_item)
        buffer.clear()

    for line in text.splitlines():
        heading = _VERSION_HEADING.match(line)
        if heading:
            flush_item()
            current = {"version": heading.group(1),
                       "date": (heading.group(2) or "").strip() or None,
                       "sections": {}}
            releases.append(current)
            section = None
            continue

        if current is None:
            continue

        sub = _SECTION_HEADING.match(line)
        if sub:
            flush_item()
            section = sub.group(1)
            continue

        if line.startswith("- "):
            flush_item()
            buffer.append(line[2:].strip())
        elif line.strip() and buffer:
            # continuation of a wrapped bullet
            buffer.append(line.strip())
        elif not line.strip():
            flush_item()

    flush_item()
    return releases


def load_releases() -> list[dict]:
    path = changelog_path()
    if path is None:
        logger.debug("CHANGELOG.md not found; changelog tool will report none")
        return []
    try:
        return parse_changelog(path.read_text(encoding="utf-8"))
    except OSError as e:
        logger.warning("could not read %s: %s", path, e)
        return []


def releases_since(releases: list[dict], since: str | None) -> list[dict]:
    """Releases strictly newer than `since`. Unknown/absent `since` returns all.

    An unparseable version returns everything rather than nothing: showing too
    much is recoverable, showing nothing would let a stale session conclude
    that nothing changed.
    """
    if not since:
        return releases
    try:
        floor = _version_key(since.strip().lstrip("v"))
    except (ValueError, AttributeError):
        logger.debug("unparseable `since` value %r; returning all releases", since)
        return releases
    out = []
    for release in releases:
        try:
            if _version_key(release["version"]) > floor:
                out.append(release)
        except ValueError:
            out.append(release)
    return out


def unlearn_items(releases: list[dict]) -> list[dict]:
    """Every 'Unlearn' entry, newest first.

    Surfaced separately because these are the ones that matter to a session
    holding stale assumptions -- a changed contract produces a confidently wrong
    answer, where a missing feature merely fails.
    """
    out = []
    for release in releases:
        for name, items in release["sections"].items():
            if name.strip().lower().startswith("unlearn"):
                for item in items:
                    out.append({"version": release["version"], "item": item})
    return out
