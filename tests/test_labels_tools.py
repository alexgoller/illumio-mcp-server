"""Unit tests for the label tools. No PCE required -- ctx.pce is stubbed.

Covers the exact-vs-partial matching contract of get-labels, which an
integration test cannot assert reliably (it depends on which label keys happen
to exist on the target PCE).
"""
import ast
import re

from illumio_mcp.context import ToolContext
from illumio_mcp.tools.labels import handle_get_labels


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class FakePCE:
    """Mimics the PCE's substring matching on ?key= and ?value=."""

    def __init__(self, labels):
        self._labels = labels
        self.last_params = None

    def get(self, endpoint, params=None):
        assert endpoint == '/labels'
        self.last_params = dict(params or {})
        rows = self._labels
        if 'key' in self.last_params:
            rows = [r for r in rows if self.last_params['key'] in r['key']]
        if 'value' in self.last_params:
            rows = [r for r in rows if self.last_params['value'] in r['value']]
        return FakeResponse(rows)


LABELS = [
    {"href": "/orgs/1/labels/1", "key": "role", "value": "web"},
    {"href": "/orgs/1/labels/2", "key": "role", "value": "database"},
    {"href": "/orgs/1/labels/3", "key": "servicerole", "value": "webproxy"},
    {"href": "/orgs/1/labels/4", "key": "app", "value": "pos"},
]


def _parse(result):
    text = result[0].text
    match = re.match(r"Labels:\s*(\[.*\])", text, re.DOTALL)
    assert match, f"unexpected output shape: {text[:200]!r}"
    return ast.literal_eval(match.group(1))


def _ctx(labels=LABELS):
    pce = FakePCE(labels)
    return ToolContext(pce=pce, is_stdio=True), pce


def test_key_filter_is_exact_not_substring():
    """Regression: ?key=role must not return 'servicerole' labels.

    The PCE matches key as a substring, so narrowing happens client-side.
    """
    ctx, _ = _ctx()
    labels = _parse(handle_get_labels(ctx, {"key": "role"}))
    assert {l["key"] for l in labels} == {"role"}
    assert sorted(l["value"] for l in labels) == ["database", "web"]


def test_key_filter_still_narrows_server_side():
    """The key is still sent to the PCE, so we do not fetch the whole label set."""
    ctx, pce = _ctx()
    handle_get_labels(ctx, {"key": "role"})
    assert pce.last_params.get("key") == "role"


def test_value_filter_remains_partial():
    """`value` documents partial matching -- that behaviour is deliberate."""
    ctx, _ = _ctx()
    labels = _parse(handle_get_labels(ctx, {"value": "web"}))
    assert sorted(l["value"] for l in labels) == ["web", "webproxy"]


def test_key_and_value_filters_combine():
    ctx, _ = _ctx()
    labels = _parse(handle_get_labels(ctx, {"key": "role", "value": "web"}))
    assert [(l["key"], l["value"]) for l in labels] == [("role", "web")]


def test_no_key_filter_returns_everything():
    ctx, _ = _ctx()
    assert len(_parse(handle_get_labels(ctx, {}))) == len(LABELS)


def test_key_with_no_exact_match_returns_empty():
    """A key that only matches as a substring must yield nothing."""
    ctx, _ = _ctx()
    assert _parse(handle_get_labels(ctx, {"key": "rol"})) == []


def test_malformed_rows_do_not_crash_the_key_filter():
    """A non-dict row in the PCE payload must be skipped, not raise."""
    ctx, _ = _ctx(labels=[{"href": "/orgs/1/labels/4", "key": "app", "value": "pos"}])
    ctx.pce._labels = ctx.pce._labels + ["unexpected-string-row"]  # type: ignore[list-item]
    ctx.pce.get = lambda endpoint, params=None: FakeResponse(ctx.pce._labels)
    assert [l["value"] for l in _parse(handle_get_labels(ctx, {"key": "app"}))] == ["pos"]
