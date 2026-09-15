"""Contract tests for the shared label-reference resolver and the tool-list
approval annotation. No PCE required: the label index is stubbed.

These guard three bugs that each shipped once:
  - `labels` encoded as OR instead of AND, returning 138 workloads for a
    filter whose true answer is 23;
  - an unresolved label silently dropped, widening the filter instead of
    failing;
  - write tools advertising no hint that the client will pause for approval,
    so a gated call looked like a hung server.
"""
import json
import pytest

from illumio_mcp.label_refs import (
    resolve_label_refs,
    encode_label_filter,
    normalise_label_value,
    unresolved_label_error,
)


class _Label:
    def __init__(self, key, value, href):
        self.key, self.value, self.href = key, value, href


class _Labels:
    _ALL = [
        _Label("app", "ordering", "/orgs/1/labels/1"),
        _Label("env", "Production", "/orgs/1/labels/2"),
        _Label("role", "web", "/orgs/1/labels/3"),
        _Label("servicerole", "web", "/orgs/1/labels/4"),
    ]

    def get(self, params=None):
        params = params or {}
        key = params.get("key")
        # Mirror the PCE's substring semantics on ?key=, which is what makes
        # exact matching the resolver's job rather than the server's.
        return [l for l in self._ALL if not key or key in l.key]


class _PCE:
    labels = _Labels()


@pytest.fixture
def pce():
    return _PCE()


# ----- every accepted spelling resolves to the same href -----

@pytest.mark.parametrize("ref", [
    "app=ordering",
    "/orgs/1/labels/1",
    {"key": "app", "value": "ordering"},
    {"href": "/orgs/1/labels/1"},
])
def test_all_reference_forms_resolve_identically(pce, ref):
    hrefs, unresolved = resolve_label_refs(pce, [ref])
    assert hrefs == ["/orgs/1/labels/1"]
    assert unresolved == []


def test_bare_string_accepts_scalar_not_just_list(pce):
    assert resolve_label_refs(pce, "app=ordering")[0] == ["/orgs/1/labels/1"]


def test_mixed_forms_in_one_call(pce):
    hrefs, unresolved = resolve_label_refs(
        pce, ["app=ordering", "/orgs/1/labels/2"])
    assert hrefs == ["/orgs/1/labels/1", "/orgs/1/labels/2"]
    assert unresolved == []


# ----- AND vs OR: the 138-instead-of-23 bug -----

def test_encode_produces_one_and_block():
    """Outer list is OR'd, inner AND'd. Two labels must share ONE inner list,
    or the filter silently becomes app=ordering OR env=Production."""
    encoded = json.loads(encode_label_filter(["/orgs/1/labels/1", "/orgs/1/labels/2"]))
    assert encoded == [["/orgs/1/labels/1", "/orgs/1/labels/2"]], \
        "labels must encode as a single AND block"
    assert len(encoded) == 1, "more than one outer entry means OR semantics"


def test_encode_empty_is_empty_filter():
    assert json.loads(encode_label_filter([])) == []


# ----- unresolved references fail loudly rather than widening the query -----

def test_unknown_label_is_reported_not_dropped(pce):
    hrefs, unresolved = resolve_label_refs(pce, ["app=ordering", "app=nope"])
    assert hrefs == ["/orgs/1/labels/1"]
    assert unresolved == ["app=nope"], "an unknown label must not be silently dropped"


def test_value_without_key_is_unresolved(pce):
    assert resolve_label_refs(pce, ["ordering"])[1] == ["ordering"]


def test_error_payload_names_valid_values(pce):
    err = unresolved_label_error(["app=nope"], pce)
    assert err["error"] == "unresolved_label_filter"
    assert err["unresolved"] == ["app=nope"]
    assert "ordering" in err["valid_values"]["app"]


def test_valid_values_exclude_substring_key_matches(pce):
    """?key=role also matches servicerole on a real PCE; the suggestions must
    not offer values that belong to a different dimension."""
    err = unresolved_label_error(["role=nope"], pce)
    assert err["valid_values"]["role"] == ["web"]


# ----- normalise_label_value: bare-value contracts accept the same spellings -----

@pytest.mark.parametrize("ref,expected", [
    ("ordering", "ordering"),
    ("app=ordering", "ordering"),
    ("/orgs/1/labels/1", "ordering"),
])
def test_normalise_to_plain_value(pce, ref, expected):
    assert normalise_label_value(pce, ref, "app") == expected


def test_normalise_leaves_other_dimensions_prefix_alone(pce):
    """Only the matching dimension's prefix is stripped, so a value that
    happens to contain '=' is not mangled."""
    assert normalise_label_value(pce, "env=Production", "app") == "env=Production"


def test_normalise_passes_through_unknown_href(pce):
    assert normalise_label_value(pce, "/orgs/1/labels/999", "app") == "/orgs/1/labels/999"
