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


def test_workload_label_filter_is_one_and_group():
    """All hrefs in a single block, which is the AND.

    Measured on demo100, where 23 hosts genuinely carry both labels:
        flat [a, b]  -> 406 invalid_uri
        [[a, b]]     ->  23 workloads   (ground truth)
        [[a], [b]]   -> 138 workloads   (the union: 32 + 129 - 23)

    An earlier version of this test asserted [[a], [b]] and passed, because the
    PCE it was written against had no host carrying both labels."""
    assert json.loads(_label_filter([APP, ENV])) == [[APP, ENV]]


def test_single_label_still_wrapped():
    assert json.loads(_label_filter([APP])) == [[APP]]


def test_traffic_filters_are_not_split_into_separate_blocks():
    """Separate blocks OR the labels and silently widen the scope."""
    import pathlib as _p
    for name in ("ringfence.py", "policy.py"):
        src = (_p.Path("src/illumio_mcp/tools") / name).read_text()
        assert "[[app_filter], [env_filter]]" not in src, name


def test_empty_filter_is_empty_list():
    assert json.loads(_label_filter([])) == []


def test_filter_is_json_encoded_not_a_python_repr():
    """The PCE echoes a bad value back brace-wrapped, which reads like a Python
    set and sends you hunting in the wrong place. Encode explicitly."""
    encoded = _label_filter([APP, ENV])
    assert isinstance(encoded, str)
    assert "'" not in encoded and "{" not in encoded
