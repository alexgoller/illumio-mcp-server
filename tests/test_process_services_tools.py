"""Tool-level guards for process-qualified services and service references.

These cover the three PCE behaviours that silently produce the wrong policy,
each measured against a live PCE rather than assumed:

  1. A service carries an OS type. Supplying service_ports together with
     windows_* makes the PCE keep one list, NULL the others, and return 201.
  2. windows_egress_services takes process_name/service_name only; a port there
     is refused with a raw schema dump.
  3. A Windows egress service in a rule's ingress_services is refused with
     `ingress_service_cannot_be_windows_egress_service` and no hint that the
     field it belongs in is `egress_services`.
"""
import json
import pytest

from illumio_mcp.tools.services import handle_create_service
from illumio_mcp.tools.sec_rules import handle_update_sec_rule, handle_delete_sec_rule
from illumio_mcp.service_refs import reject_egress_service_in_ingress
from illumio_mcp.tools import TOOL_REGISTRY

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
EGRESS_HREF = "/orgs/1/sec_policy/draft/services/6"


class _Ctx:
    def __init__(self, pce): self.pce = pce


class _Resp:
    def __init__(self, body): self._body = body
    def raise_for_status(self): pass
    def json(self): return self._body


class _PCE:
    """Fails the test if a call reaches the PCE; these guards must fire first."""
    _hostname, org_id = "pce.test", 1
    def __init__(self): self.posts = []
    def post(self, endpoint, json=None):
        self.posts.append((endpoint, json))
        raise AssertionError(f"guard did not fire; POST reached the PCE: {endpoint}")
    def get(self, endpoint, params=None, include_org=False):
        if endpoint == EGRESS_HREF:
            return _Resp({"name": "S-EGRESS", "href": EGRESS_HREF,
                          "windows_egress_services": [{"process_name": CHROME}]})
        return _Resp([])


def _call(handler, args, pce=None):
    return json.loads(handler(_Ctx(pce or _PCE()), args)[0].text)


# ----- service list exclusivity -----

def test_ports_plus_egress_refused_before_any_write():
    """The PCE would accept this and silently discard service_ports."""
    r = _call(handle_create_service, {
        "name": "S-X",
        "service_ports": [{"port": 443, "proto": 6}],
        "windows_egress_services": [{"process_name": CHROME}]})
    assert r["error"] == "conflicting_service_definition"
    assert set(r["supplied"]) == {"service_ports", "windows_egress_services"}


def test_conflict_error_explains_which_list_to_pick():
    r = _call(handle_create_service, {
        "name": "S-X", "service_ports": [{"port": 443, "proto": 6}],
        "windows_services": [{"process_name": CHROME}]})
    assert "guidance" in r
    blob = json.dumps(r["guidance"])
    assert "CONSUMER" in blob and "PROVIDER" in blob


def test_all_three_lists_together_refused():
    r = _call(handle_create_service, {
        "name": "S-X", "service_ports": [{"port": 1, "proto": 6}],
        "windows_services": [{"port": 2, "proto": 6}],
        "windows_egress_services": [{"process_name": CHROME}]})
    assert r["error"] == "conflicting_service_definition"
    assert len(r["supplied"]) == 3


def test_service_with_no_qualifiers_refused():
    r = _call(handle_create_service, {"name": "S-EMPTY"})
    assert r["error"] == "empty_service"


def test_port_in_egress_list_refused_with_guidance():
    r = _call(handle_create_service, {
        "name": "S-X", "windows_egress_services": [{"process_name": CHROME, "port": 443}]})
    assert r["error"] == "invalid_service_definition"
    assert "service_ports" in r["message"]


def test_egress_only_service_is_valid_input():
    """Must NOT be rejected by validation -- it is the shape the demo depends on.

    The fake PCE raises on POST, and the handler turns that into a generic
    error, so the assertion is that validation was PASSED (the request reached
    the POST) rather than refused up front.
    """
    pce = _PCE()
    r = _call(handle_create_service,
              {"name": "S-OK", "windows_egress_services": [{"process_name": CHROME}]},
              pce=pce)
    assert r.get("error") not in ("conflicting_service_definition",
                                  "invalid_service_definition", "empty_service")
    assert pce.posts, "validation passed but no PCE call was attempted"
    endpoint, payload = pce.posts[0]
    assert endpoint == "/sec_policy/draft/services"
    assert payload["windows_egress_services"] == [{"process_name": CHROME}]
    assert "service_ports" not in payload


# ----- egress service in the wrong rule field -----

def test_egress_service_in_ingress_is_caught_with_the_right_field_named():
    msg = reject_egress_service_in_ingress(_PCE(), [{"href": EGRESS_HREF}])
    assert msg and "egress_services" in msg
    assert "ingress_services" in msg


def test_plain_service_in_ingress_is_fine():
    class _Plain(_PCE):
        def get(self, endpoint, params=None, include_org=False):
            return _Resp({"name": "S-HTTP", "href": endpoint,
                          "service_ports": [{"port": 80, "proto": 6}]})
    assert reject_egress_service_in_ingress(_Plain(), [{"href": "/orgs/1/x/1"}]) is None


def test_inline_ports_are_not_inspected():
    """No href, so no lookup -- the check must not cost a call per inline port."""
    assert reject_egress_service_in_ingress(_PCE(), [{"port": 443, "proto": 6}]) is None


# ----- sec-rule href validation -----

@pytest.mark.parametrize("handler", [handle_update_sec_rule, handle_delete_sec_rule])
def test_deny_rule_href_rejected_with_a_pointer_to_the_right_tool(handler):
    r = _call(handler, {"href": "/orgs/1/sec_policy/draft/rule_sets/2/deny_rules/3"})
    assert r["error"] == "invalid_href"
    assert "deny-rule" in r["message"]


def test_update_with_no_fields_is_refused():
    r = _call(handle_update_sec_rule,
              {"href": "/orgs/1/sec_policy/draft/rule_sets/2/sec_rules/3"})
    assert r["error"] == "no_update_fields"


# ----- registry wiring -----

@pytest.mark.parametrize("name", ["update-sec-rule", "delete-sec-rule"])
def test_new_tools_are_registered_as_mutating(name):
    spec = TOOL_REGISTRY[name]
    assert spec.mutating is True, "must carry the client-approval annotation"
    assert spec.requires_pce is True
