"""Label-filter encoding for PCE queries. No PCE required.

Two distinct APIs, both of which were being handed a flat list where the PCE
expects a list of AND-groups. Both failed in ways that looked like "no data"
rather than "bad request", which is the dangerous shape: a ringfence that
reports zero remote apps looks like a clean result.
"""
import json

from illumio_mcp.tools.policy import _label_filter


APP = "/orgs/1/labels/48"
ENV = "/orgs/1/labels/126"


def test_workload_label_filter_wraps_each_href_in_its_own_group():
    """Verified against a live PCE: flat -> 406 invalid_uri,
    [[a, b]] -> 0 workloads, [[a], [b]] -> 33 workloads."""
    assert json.loads(_label_filter([APP, ENV])) == [[APP], [ENV]]


def test_single_label_still_wrapped():
    assert json.loads(_label_filter([APP])) == [[APP]]


def test_empty_filter_is_empty_list():
    assert json.loads(_label_filter([])) == []


def test_filter_is_json_encoded_not_a_python_repr():
    """The PCE echoes a bad value back brace-wrapped, which reads like a Python
    set and sends you hunting in the wrong place. Encode explicitly."""
    encoded = _label_filter([APP, ENV])
    assert isinstance(encoded, str)
    assert "'" not in encoded and "{" not in encoded


def test_traffic_query_filters_are_separate_and_blocks():
    """include_destinations=[[app, env]] returns 0 flows on a live PCE;
    [[app], [env]] returns 278. One AND-block containing both labels is not
    the same as two AND-blocks, and the PCE satisfies only the latter."""
    import pathlib
    for name in ("ringfence.py", "policy.py"):
        src = (pathlib.Path("src/illumio_mcp/tools") / name).read_text()
        assert "[[app_filter, env_filter]]" not in src, (
            f"{name} still combines app and env into one AND-block; "
            "that query returns no flows"
        )
