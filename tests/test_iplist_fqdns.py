"""FQDN IP lists through create-iplist / update-iplist.

Reported from the field: "FQDN IPList creation doesn't work with the MCP
server." Reproduced on demo100 (26.30.4), 2026-10-31:

  create-iplist {name, fqdn: "*.example.com"}
      -> KeyError: 'ip_ranges'            (handler and schema required ranges)
  create-iplist {name, fqdn: "...", ip_ranges: []}
      -> PCE 406: additional properties ["fqdn"] outside of the schema
                                          (the field is `fqdns`, a list of
                                           {fqdn, description})

So an FQDN list was never creatable here. These tests pin the payload the PCE
accepts and the shapes a caller may pass.
"""
import json
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools.iplists import handle_create_iplist, handle_update_iplist


class FakeIPLists:
    def __init__(self):
        self.created = []; self.updated = []; self.existing = []
    def get(self, params=None, **kw):
        return [l for l in self.existing if l.name == (params or {}).get("name")]
    def create(self, data):
        self.created.append(data)
        obj = NS(href="/orgs/1/sec_policy/draft/ip_lists/9", name=data["name"], description=data.get("description"),
                 ip_ranges=[NS(from_ip=r["from_ip"], to_ip=r.get("to_ip"), description=r.get("description"),
                               exclusion=r.get("exclusion", False)) for r in data.get("ip_ranges", [])],
                 fqdns=[NS(fqdn=f["fqdn"], description=f.get("description")) for f in data.get("fqdns", [])])
        self.existing.append(obj); return obj
    def update(self, href, data):
        self.updated.append((href, data))
    def get_by_reference(self, href):
        obj = next(l for l in self.existing if l.href == href)
        if self.updated:
            data = self.updated[-1][1]
            if "fqdns" in data:
                obj.fqdns = [NS(fqdn=f["fqdn"], description=f.get("description")) for f in data["fqdns"]]
            if "ip_ranges" in data:
                obj.ip_ranges = [NS(from_ip=r["from_ip"], to_ip=r.get("to_ip"), description=r.get("description"),
                                    exclusion=r.get("exclusion", False)) for r in data["ip_ranges"]]
        return obj


def _ctx():
    pce = NS(ip_lists=FakeIPLists()); return ToolContext(pce=pce, is_stdio=True), pce


def _create(args):
    ctx, pce = _ctx()
    return json.loads(handle_create_iplist(ctx, args)[0].text), pce


def test_fqdn_only_list_is_created_with_the_pce_field_name():
    out, pce = _create({"name": "saas-vendor", "fqdns": ["*.example.com", "api.example.com"]})
    assert "error" not in out, out
    sent = pce.ip_lists.created[0]
    assert sent["fqdns"] == [{"fqdn": "*.example.com"}, {"fqdn": "api.example.com"}]
    assert "fqdn" not in sent and sent.get("ip_ranges", []) == []
    assert [f["fqdn"] for f in out["fqdns"]] == ["*.example.com", "api.example.com"]


def test_fqdn_entries_may_carry_a_description():
    out, pce = _create({"name": "x", "fqdns": [{"fqdn": "*.example.com", "description": "vendor CDN"}]})
    assert pce.ip_lists.created[0]["fqdns"] == [{"fqdn": "*.example.com", "description": "vendor CDN"}]
    assert out["fqdns"][0]["description"] == "vendor CDN"


def test_legacy_singular_fqdn_argument_still_works():
    """The old schema exposed `fqdn` as one string; sessions that learned it
    keep working. It was never sent correctly before, so nobody relied on the
    old (broken) behaviour."""
    out, pce = _create({"name": "x", "fqdn": "*.example.com", "ip_ranges": [{"from_ip": "10.0.0.0/8"}]})
    assert "error" not in out
    sent = pce.ip_lists.created[0]
    assert sent["fqdns"] == [{"fqdn": "*.example.com"}] and "fqdn" not in sent
    assert sent["ip_ranges"][0]["from_ip"] == "10.0.0.0/8"


def test_mixed_ranges_and_fqdns():
    out, pce = _create({"name": "x", "ip_ranges": [{"from_ip": "192.0.2.0/24"}], "fqdns": ["*.example.com"]})
    assert "error" not in out and len(out["ip_ranges"]) == 1 and len(out["fqdns"]) == 1


def test_neither_ranges_nor_fqdns_is_a_clear_error_not_a_keyerror():
    out, pce = _create({"name": "empty"})
    assert "error" in out and "ip_ranges" in out["error"] and "fqdns" in out["error"]
    assert "KeyError" not in out["error"] and pce.ip_lists.created == []


@pytest.mark.parametrize("bad", ["", " ", "not a hostname!", "http://example.com"])
def test_malformed_fqdn_is_rejected_before_the_pce_sees_it(bad):
    out, pce = _create({"name": "x", "fqdns": [bad]})
    assert "error" in out and repr(bad) in out["error"] and pce.ip_lists.created == []


def test_update_replaces_fqdns_with_the_pce_field_name():
    ctx, pce = _ctx()
    handle_create_iplist(ctx, {"name": "x", "fqdns": ["old.example.com"]})
    out = json.loads(handle_update_iplist(ctx, {"name": "x", "fqdns": ["new.example.com", "*.cdn.example.com"]})[0].text)
    assert "error" not in out, out
    href, data = pce.ip_lists.updated[0]
    assert data["fqdns"] == [{"fqdn": "new.example.com"}, {"fqdn": "*.cdn.example.com"}] and "fqdn" not in data
    assert [f["fqdn"] for f in out["fqdns"]] == ["new.example.com", "*.cdn.example.com"]


def test_update_without_fqdns_leaves_them_alone():
    ctx, pce = _ctx()
    handle_create_iplist(ctx, {"name": "x", "fqdns": ["keep.example.com"]})
    out = json.loads(handle_update_iplist(ctx, {"name": "x", "description": "renamed"})[0].text)
    assert "fqdns" not in pce.ip_lists.updated[0][1]
    assert [f["fqdn"] for f in out["fqdns"]] == ["keep.example.com"]
