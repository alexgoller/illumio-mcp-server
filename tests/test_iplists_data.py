"""Issue #49: what the illumio-unknown-endpoints skill needs from get-iplists.

Ranges and FQDNs as data rather than SDK reprs, draft OR active with the
version echoed, an exact server-side contains-IP lookup, and the default
"Any" list marked so a caller can drop it. No PCE required.
"""
import json
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools.iplists import handle_get_iplists


def _range(from_ip, to_ip=None, exclusion=False, description=None):
    return NS(from_ip=from_ip, to_ip=to_ip, exclusion=exclusion, description=description)


def _iplist(name, ranges=(), fqdns=()):
    return NS(href=f"/orgs/1/sec_policy/draft/ip_lists/{name}", name=name,
              description=f"{name} desc", ip_ranges=list(ranges),
              fqdns=[NS(fqdn=f, description=None) for f in fqdns],
              created_at="2026-01-01T00:00:00Z", updated_at="2026-01-02T00:00:00Z")


class _IPListsPCE:
    """Records what get-iplists asks the SDK for and answers with a fixed set."""

    def __init__(self, lists):
        self.calls = []

        def get(policy_version=None, params=None):
            self.calls.append({"policy_version": policy_version, "params": dict(params or {})})
            return lists
        self.ip_lists = NS(get=get)


ANY = _iplist("Any (0.0.0.0/0 and ::/0)", [_range("0.0.0.0/0"), _range("::/0")])
CORP = _iplist("IPL-CORP", [_range("10.0.0.0/8", description="RFC1918 A"),
                            _range("10.99.0.0/16", exclusion=True, description="lab, not corp")],
               fqdns=["*.corp.example.com"])
SPAN = _iplist("IPL-SPAN", [_range("192.168.1.10", to_ip="192.168.1.20")])
HOST = _iplist("IPL-HOST", [_range("172.16.5.5")])
V6 = _iplist("IPL-V6", [_range("2001:db8::/32"), _range("2001:db8:ffff::/48", exclusion=True)])
ALL = [ANY, CORP, SPAN, HOST, V6]


def _call(lists, args):
    pce = _IPListsPCE(lists)
    out = handle_get_iplists(ToolContext(pce=pce, is_stdio=True), args)
    return json.loads(out[0].text), pce


def _names(payload):
    return [l["name"] for l in payload["ip_lists"]]


# ----- shape -----

def test_ranges_and_fqdns_are_data_not_reprs():
    payload, _ = _call([CORP], {})
    lst = payload["ip_lists"][0]
    assert lst["ip_ranges"] == [
        {"from_ip": "10.0.0.0/8", "to_ip": None, "exclusion": False, "description": "RFC1918 A"},
        {"from_ip": "10.99.0.0/16", "to_ip": None, "exclusion": True, "description": "lab, not corp"},
    ]
    assert lst["fqdns"] == [{"fqdn": "*.corp.example.com", "description": None}]
    assert lst["created_at"] == "2026-01-01T00:00:00Z"
    assert lst["updated_at"] == "2026-01-02T00:00:00Z"
    assert "IPRange(" not in json.dumps(payload)


def test_envelope_keeps_ip_lists_and_total_count_and_adds_policy_version():
    payload, _ = _call(ALL, {})
    assert set(payload) == {"policy_version", "ip_lists", "total_count"}
    assert payload["total_count"] == len(ALL)
    assert payload["policy_version"] == "draft"


def test_is_default_marks_only_the_any_list():
    payload, _ = _call(ALL, {})
    flags = {l["name"]: l["is_default"] for l in payload["ip_lists"]}
    assert flags[ANY.name] is True
    assert all(v is False for n, v in flags.items() if n != ANY.name)


@pytest.mark.parametrize("ranges", [[_range("0.0.0.0/0")], [_range("::/0")]])
def test_is_default_for_either_address_family_alone(ranges):
    payload, _ = _call([_iplist("x", ranges)], {})
    assert payload["ip_lists"][0]["is_default"] is True


def test_a_default_range_used_as_exclusion_is_not_a_default_list():
    payload, _ = _call([_iplist("x", [_range("10.0.0.0/8"), _range("0.0.0.0/0", exclusion=True)])], {})
    assert payload["ip_lists"][0]["is_default"] is False


# ----- pversion -----

def test_pversion_defaults_to_draft_and_is_passed_to_the_sdk():
    payload, pce = _call(ALL, {})
    assert pce.calls[0]["policy_version"] == "draft"
    assert payload["policy_version"] == "draft"


def test_pversion_active_is_passed_through_and_echoed():
    payload, pce = _call(ALL, {"pversion": "active"})
    assert pce.calls[0]["policy_version"] == "active"
    assert payload["policy_version"] == "active"


def test_pversion_rejects_anything_else():
    payload, pce = _call(ALL, {"pversion": "staged"})
    assert "error" in payload and "pversion" in payload["error"]
    assert pce.calls == []


# ----- contains_ip -----

def test_contains_ip_inside_a_cidr():
    payload, _ = _call(ALL, {"contains_ip": "10.20.30.40"})
    assert _names(payload) == [ANY.name, CORP.name]
    corp = payload["ip_lists"][1]
    assert corp["matched_range"]["from_ip"] == "10.0.0.0/8"
    assert payload["total_count"] == 2
    assert payload["contains_ip"] == "10.20.30.40"


def test_contains_ip_honours_an_exclusion_range():
    payload, _ = _call([CORP], {"contains_ip": "10.99.4.4"})
    assert payload["ip_lists"] == []
    assert payload["total_count"] == 0


def test_contains_ip_inside_a_from_to_span():
    hit, _ = _call([SPAN], {"contains_ip": "192.168.1.15"})
    assert _names(hit) == [SPAN.name]
    assert hit["ip_lists"][0]["matched_range"] == {
        "from_ip": "192.168.1.10", "to_ip": "192.168.1.20", "exclusion": False, "description": None}
    for edge in ("192.168.1.10", "192.168.1.20"):
        assert _names(_call([SPAN], {"contains_ip": edge})[0]) == [SPAN.name]
    for miss in ("192.168.1.9", "192.168.1.21"):
        assert _call([SPAN], {"contains_ip": miss})[0]["ip_lists"] == []


def test_contains_ip_single_address_range_is_exact():
    assert _names(_call([HOST], {"contains_ip": "172.16.5.5"})[0]) == [HOST.name]
    assert _call([HOST], {"contains_ip": "172.16.5.50"})[0]["ip_lists"] == []


def test_contains_ip_ipv6():
    hit, _ = _call(ALL, {"contains_ip": "2001:db8:1::5"})
    assert _names(hit) == [ANY.name, V6.name]
    assert hit["ip_lists"][1]["matched_range"]["from_ip"] == "2001:db8::/32"
    excluded, _ = _call([V6], {"contains_ip": "2001:db8:ffff::1"})
    assert excluded["ip_lists"] == []


def test_contains_ip_does_not_cross_address_families():
    """0.0.0.0/0 must not claim an IPv6 address and ::/0 must not claim IPv4."""
    v4only = _iplist("v4", [_range("0.0.0.0/0")])
    v6only = _iplist("v6", [_range("::/0")])
    assert _call([v4only, v6only], {"contains_ip": "2001:db8::1"})[0]["ip_lists"][0]["name"] == "v6"
    assert _call([v4only, v6only], {"contains_ip": "8.8.8.8"})[0]["ip_lists"][0]["name"] == "v4"


def test_contains_ip_lets_a_caller_drop_the_default_list():
    """The skill's question: unknown-but-inside-list-X versus in-no-list."""
    payload, _ = _call(ALL, {"contains_ip": "203.0.113.9"})
    real = [l for l in payload["ip_lists"] if not l["is_default"]]
    assert _names(payload) == [ANY.name] and real == []


def test_contains_ip_rejects_a_cidr_or_garbage():
    for bad in ("10.0.0.0/8", "not-an-ip", "10.0.0"):
        payload, pce = _call(ALL, {"contains_ip": bad})
        assert "error" in payload and "contains_ip" in payload["error"]
        assert pce.calls == []


def test_unparseable_range_text_does_not_match_or_crash():
    weird = _iplist("weird", [_range("10.0.0.0-10.0.0.255"), _range(None)])
    payload, _ = _call([weird, HOST], {"contains_ip": "172.16.5.5"})
    assert _names(payload) == [HOST.name]
    shape, _ = _call([weird], {})
    assert shape["ip_lists"][0]["is_default"] is False


def test_matched_range_is_absent_without_contains_ip():
    payload, _ = _call(ALL, {})
    assert all("matched_range" not in l for l in payload["ip_lists"])


# ----- the old partial filters still reach the PCE -----

def test_existing_substring_filters_are_passed_through_unchanged():
    _, pce = _call(ALL, {"name": "CORP", "description": "RFC", "fqdn": "example",
                         "ip_address": "10.20", "max_results": 5})
    assert pce.calls[0]["params"] == {
        "name": "CORP", "description": "RFC", "fqdn": "example",
        "ip_address": "10.20", "max_results": 5}


def test_contains_ip_is_not_sent_to_the_pce():
    _, pce = _call(ALL, {"contains_ip": "10.0.0.1"})
    assert "contains_ip" not in pce.calls[0]["params"]
    assert pce.calls[0]["params"] == {"max_results": 10000}


# ----- the advertised schema -----

def test_schema_advertises_the_new_arguments():
    import asyncio
    from illumio_mcp.server import handle_list_tools
    tool = next(t for t in asyncio.run(handle_list_tools()) if t.name == "get-iplists")
    props = tool.inputSchema["properties"]
    assert set(props) >= {"name", "description", "fqdn", "ip_address", "contains_ip",
                          "pversion", "max_results"}
    assert props["pversion"]["enum"] == ["draft", "active"]
    assert "contains_ip" in tool.description and "is_default" in tool.description
