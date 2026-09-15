"""The changelog surface a long-running session uses to detect contract drift.

A client caches tools/list at connect time and the model forms assumptions about
tool behaviour from responses it has seen. Update the server underneath a live
session and neither refreshes -- it keeps calling tools the old way and gets
different answers with nothing announcing the change. These tests cover the
parts that fail quietly.
"""
import asyncio
import json

import pytest

from illumio_mcp.changelog import (
    parse_changelog,
    releases_since,
    unlearn_items,
    load_releases,
    changelog_path,
)
from illumio_mcp.tools.meta import handle_get_server_changelog
from illumio_mcp.tools import TOOL_REGISTRY


SAMPLE = """# Changelog

Preamble that must not be parsed as a release.

## [0.2.0] — 2026-09-15

### Added

- A thing.
- A wrapped thing that continues
  onto a second line.

### Unlearn

- `truncated` no longer exists.

## [0.1.0] — earlier

### Added

- The original thing.
"""


# ----- parsing -----

def test_parses_releases_newest_first():
    releases = parse_changelog(SAMPLE)
    assert [r["version"] for r in releases] == ["0.2.0", "0.1.0"]
    assert releases[0]["date"] == "2026-09-15"


def test_preamble_is_not_a_release():
    assert all(r["version"] != "Changelog" for r in parse_changelog(SAMPLE))


def test_wrapped_bullets_are_joined():
    added = parse_changelog(SAMPLE)[0]["sections"]["Added"]
    assert "A wrapped thing that continues onto a second line." in added


def test_sections_are_kept_separate():
    sections = parse_changelog(SAMPLE)[0]["sections"]
    assert set(sections) == {"Added", "Unlearn"}


# ----- since filtering -----

def test_since_returns_only_newer_releases():
    releases = parse_changelog(SAMPLE)
    assert [r["version"] for r in releases_since(releases, "0.1.0")] == ["0.2.0"]


def test_since_current_version_returns_nothing():
    assert releases_since(parse_changelog(SAMPLE), "0.2.0") == []


def test_since_accepts_a_v_prefix():
    assert [r["version"] for r in releases_since(parse_changelog(SAMPLE), "v0.1.0")] == ["0.2.0"]


@pytest.mark.parametrize("junk", ["banana", "", None, "not.a.version", "1.2.3.4"])
def test_unparseable_since_returns_everything_not_nothing(junk):
    """Showing too much is recoverable. Showing nothing would let a stale
    session conclude the server is unchanged, which is the failure this exists
    to prevent."""
    assert len(releases_since(parse_changelog(SAMPLE), junk)) == 2


def test_short_since_is_padded_not_truncated():
    """`since="0.2"` must mean 0.2.0. A bare 2-tuple compares as lower than
    (0, 2, 0), which would wrongly include the 0.2.0 release itself."""
    assert releases_since(parse_changelog(SAMPLE), "0.2") == []


def test_future_since_reports_nothing_newer_rather_than_erroring():
    """A session claiming a newer version than the server is a legitimate
    state, not garbage input -- report it plainly."""
    assert releases_since(parse_changelog(SAMPLE), "9.0.0") == []


def test_since_is_numeric_not_lexicographic():
    """'0.10.0' > '0.9.0' numerically but not as strings."""
    text = SAMPLE.replace("## [0.2.0]", "## [0.10.0]")
    assert releases_since(parse_changelog(text), "0.9.0") != []


# ----- unlearn extraction -----

def test_unlearn_items_are_tagged_with_their_version():
    items = unlearn_items(parse_changelog(SAMPLE))
    assert items == [{"version": "0.2.0", "item": "`truncated` no longer exists."}]


def test_unlearn_ignores_ordinary_sections():
    assert all("original thing" not in i["item"] for i in unlearn_items(parse_changelog(SAMPLE)))


# ----- the shipped changelog -----

def test_repo_changelog_is_present_and_parses():
    assert changelog_path() is not None, "CHANGELOG.md not found"
    releases = load_releases()
    assert releases, "shipped CHANGELOG.md parsed to nothing"


def test_shipped_changelog_documents_the_unlearn_items():
    """The behaviour changes that make a stale session confidently wrong."""
    items = " ".join(i["item"] for i in unlearn_items(load_releases()))
    assert "findings_truncated" in items
    assert "approval" in items.lower()


# ----- the tool -----

def test_tool_is_registered_and_needs_no_pce():
    spec = TOOL_REGISTRY["get-server-changelog"]
    assert spec.requires_pce is False, (
        "a session needs this precisely when it cannot trust its cached view; "
        "requiring a PCE would gate it behind unrelated config"
    )
    assert spec.mutating is False


def test_tool_is_advertised_with_a_schema():
    from illumio_mcp.server import handle_list_tools
    tool = next(t for t in asyncio.run(handle_list_tools())
                if t.name == "get-server-changelog")
    assert tool.inputSchema["type"] == "object"
    assert "since" in tool.inputSchema["properties"]
    assert "WRITE OPERATION" not in tool.description, "read-only tool was annotated"


def test_tool_surfaces_unlearn_before_features():
    payload = json.loads(handle_get_server_changelog(None, {})[0].text)
    assert payload["unlearn"], "no unlearn items surfaced"
    assert "note" in payload


def test_tool_reports_code_version_not_stale_dist_metadata():
    """An editable install leaves distribution metadata behind, which would
    otherwise report 0.1.0 while running 0.3.0 code."""
    payload = json.loads(handle_get_server_changelog(None, {})[0].text)
    assert payload["server_version"] == load_releases()[0]["version"]


def test_tool_handles_up_to_date_session():
    latest = load_releases()[0]["version"]
    payload = json.loads(handle_get_server_changelog(None, {"since": latest})[0].text)
    assert payload["releases"] == []
    assert "Nothing newer" in payload["note"]


def test_unlearn_only_omits_the_feature_lists():
    payload = json.loads(
        handle_get_server_changelog(None, {"unlearn_only": True})[0].text)
    assert "releases" not in payload
    assert payload["unlearn"]


def test_tool_tolerates_none_arguments():
    """Handlers are called with whatever the client sent."""
    assert json.loads(handle_get_server_changelog(None, None)[0].text)["unlearn"]


# ----- the resource -----

def test_changelog_is_exposed_as_a_resource():
    from illumio_mcp.server import handle_list_resources, CHANGELOG_URI
    uris = [str(r.uri) for r in asyncio.run(handle_list_resources())]
    assert CHANGELOG_URI in uris


def test_resource_returns_the_file_contents():
    from illumio_mcp.server import handle_read_resource, CHANGELOG_URI
    body = asyncio.run(handle_read_resource(CHANGELOG_URI))
    assert "# Changelog" in body
    assert "Unlearn" in body
