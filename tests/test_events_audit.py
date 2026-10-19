"""Issue #55: what an audit trail needs from get-events and get-rulesets.

No PCE required. get-events reads raw /events JSON; get-rulesets reads the
SDK's to_json() dicts. Both fakes answer pce.get().
"""
import json
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY
from illumio_mcp.tools.infra import (
    EVENT_KINDS, VERIFIED_EVENT_TYPES, handle_get_events, render_created_by,
)
from illumio_mcp.tools.rulesets import handle_get_rulesets

from test_app_profile_support import SHOP, L, _RulesetPCE, _rule, _ruleset


# =========================================================================
# get-events
# =========================================================================

def _event(event_type, ts="2026-10-18T10:00:00.000Z", created_by=None, **over):
    ev = {
        "href": f"/orgs/1/events/{event_type}-{ts}",
        "event_type": event_type, "timestamp": ts, "pce_fqdn": "pce.example.com",
        "severity": "info", "status": "success",
        "created_by": created_by or {"user": {"href": "/users/1", "username": "alice"}},
        "info": {}, "action": {"uuid": "u", "api_endpoint": "/api/v2/orgs/1/sec_policy",
                               "api_method": "POST", "http_status_code": 201,
                               "src_ip": "10.1.2.3"},
        "resource_changes": [], "notifications": [],
    }
    ev.update(over)
    return ev


class _EventsPCE:
    """pce.get('/events', params=...) -> the events whose event_type matches,
    or everything when no type is asked for."""
    def __init__(self, events):
        self._events = events
        self.calls = []

    def get(self, path, include_org=True, params=None, **kw):
        assert path == "/events" and include_org
        self.calls.append(dict(params or {}))
        et = (params or {}).get("event_type")
        hits = sorted((e for e in self._events if et is None or e["event_type"] == et),
                      key=lambda e: e["timestamp"], reverse=True)      # PCE: newest first
        hits = hits[: int((params or {}).get("max_results") or 100)]
        return NS(json=lambda: hits)


def _events(pce, args):
    out = handle_get_events(ToolContext(pce=pce, is_stdio=True), args)
    return json.loads(out[0].text)


def test_registered_read_only():
    spec = TOOL_REGISTRY["get-events"]
    assert not spec.mutating and not spec.requires_confirm


@pytest.mark.parametrize("raw, expected", [
    ({"user": {"href": "/users/1", "username": "alice"}},
     {"type": "user", "username": "alice", "href": "/users/1"}),
    ({"agent": {"href": "/orgs/1/agents/7", "hostname": "web01"}},
     {"type": "agent", "username": "web01", "href": "/orgs/1/agents/7"}),
    ({"system": {}}, {"type": "system", "username": None, "href": None}),
    (None, None),
    ({}, None),
    ("{'user': ...}", None),
])
def test_created_by_is_an_object_not_dict_text(raw, expected):
    """Reported: created_by was str() of the PCE dict -- single-quoted
    pseudo-JSON the caller had to parse by hand."""
    assert render_created_by(raw) == expected


def test_events_render_created_by_resource_changes_notifications_and_action():
    ev = _event("rule_set.update", resource_changes=[{
        "uuid": "x", "version": 3, "org_id": 1, "change_type": "update",
        "resource": {"rule_set": {"href": "/orgs/1/sec_policy/draft/rule_sets/5", "name": "RS-SHOP"}},
        "changes": {"enabled": {"from": True, "to": False}},
    }], notifications=[{"uuid": "n", "notification_type": "rule_set.update", "info": {"a": 1}}])
    out = _events(_EventsPCE([ev]), {})
    e = out["events"][0]
    assert e["created_by"] == {"type": "user", "username": "alice", "href": "/users/1"}
    assert e["resource_changes"] == [{
        "resource_type": "rule_set", "href": "/orgs/1/sec_policy/draft/rule_sets/5",
        "name": "RS-SHOP", "change_type": "update",
        "changes": {"enabled": {"from": True, "to": False}},
    }]
    assert e["notifications"] == [{"notification_type": "rule_set.update", "info": {"a": 1}}]
    assert e["action"] == {"api_endpoint": "/api/v2/orgs/1/sec_policy", "api_method": "POST",
                           "src_ip": "10.1.2.3", "http_status_code": 201}
    assert "notification_type" not in e
    assert "{'" not in json.dumps(out)


def test_empty_lists_are_omitted_not_emitted_as_noise():
    e = _events(_EventsPCE([_event("user.login", action=None)]), {})["events"][0]
    assert "resource_changes" not in e and "notifications" not in e and "action" not in e


def test_single_event_type_is_passed_to_the_pce():
    pce = _EventsPCE([_event("user.login")])
    out = _events(pce, {"event_type": "user.login", "severity": "info"})
    assert pce.calls == [{"event_type": "user.login", "severity": "info", "max_results": 100}]
    assert out["event_types_queried"] == ["user.login"]


def test_event_type_list_is_or_and_merged_newest_first():
    """The PCE filters on one event_type per request; a list is one request
    per type, merged by timestamp, each event once."""
    pce = _EventsPCE([
        _event("rule_set.update", "2026-10-18T09:00:00Z"),
        _event("sec_rule.create", "2026-10-18T11:00:00Z"),
        _event("user.login", "2026-10-18T12:00:00Z"),
    ])
    out = _events(pce, {"event_type": ["rule_set.update", "sec_rule.create"]})
    assert [c["event_type"] for c in pce.calls] == ["rule_set.update", "sec_rule.create"]
    assert [e["event_type"] for e in out["events"]] == ["sec_rule.create", "rule_set.update"]
    assert out["total_count"] == 2 and out["truncated"] is False


def test_merged_results_are_capped_at_max_results():
    pce = _EventsPCE([_event("rule_set.update", f"2026-10-18T0{i}:00:00Z") for i in range(5)]
                     + [_event("sec_rule.create", f"2026-10-18T1{i}:00:00Z") for i in range(5)])
    out = _events(pce, {"event_type": ["rule_set.update", "sec_rule.create"], "max_results": 3})
    assert out["total_count"] == 3 and out["truncated"] is True
    assert [e["timestamp"] for e in out["events"]] == [
        "2026-10-18T14:00:00Z", "2026-10-18T13:00:00Z", "2026-10-18T12:00:00Z"]


def test_kind_policy_maps_to_the_documented_strings():
    pce = _EventsPCE([_event("sec_policy.create"), _event("rule_set.create"),
                      _event("user.login"), _event("agent.activate")])
    out = _events(pce, {"kind": "policy"})
    assert out["kind"] == "policy"
    assert out["event_types_queried"] == EVENT_KINDS["policy"]
    assert {c["event_type"] for c in pce.calls} == set(EVENT_KINDS["policy"])
    assert {e["event_type"] for e in out["events"]} == {"sec_policy.create", "rule_set.create"}
    for needed in ("sec_policy.create", "rule_set.create", "rule_set.update", "rule_set.delete",
                   "sec_rule.create", "sec_rule.update", "sec_rule.delete",
                   "ip_list.update", "service.update"):
        assert needed in EVENT_KINDS["policy"]


def test_kind_enforcement_uses_the_verified_bulk_update_name():
    """Live: enforcement edits on demo100 are workloads.bulk_update with
    changes = {enforcement_mode: {before, after}}; workloads.update does not exist."""
    assert "workloads.bulk_update" in EVENT_KINDS["enforcement"]
    assert "workloads.bulk_update" in VERIFIED_EVENT_TYPES
    assert "workloads.update" not in EVENT_KINDS["enforcement"]


def test_response_says_which_queried_types_are_unverified():
    out = _events(_EventsPCE([]), {"event_type": ["rule_set.update", "sec_policy.create"]})
    assert out["event_types_unverified"] == ["sec_policy.create"]


def test_kind_ven_and_auth_cover_pairing_and_login():
    assert {"agent.activate", "agent.deactivate", "agent.tampering"} <= set(EVENT_KINDS["ven"])
    assert {"user.login", "user.logout"} <= set(EVENT_KINDS["auth"])
    assert "request.authorization_failed" in VERIFIED_EVENT_TYPES


def test_kind_and_event_type_combine_without_duplicates():
    pce = _EventsPCE([_event("user.login"), _event("agent.tampering")])
    out = _events(pce, {"kind": "auth", "event_type": ["agent.tampering", "user.login"]})
    queried = out["event_types_queried"]
    assert len(queried) == len(set(queried))
    assert {e["event_type"] for e in out["events"]} == {"user.login", "agent.tampering"}


def test_unknown_kind_is_rejected():
    out = _events(_EventsPCE([]), {"kind": "everything"})
    assert "error" in out and "policy" in out["error"]


def test_kind_enforcement_keeps_mode_changes_and_unparseable_changes_only():
    """Enforcement mode changes are workload.update events; a workload.update
    that only relabelled is not one. An event whose changes the PCE did not
    spell out is kept -- dropping it would hide a mode flip."""
    mode = _event("workload.update", "2026-10-18T10:00:00Z", resource_changes=[{
        "resource": {"workload": {"href": "/orgs/1/workloads/1", "name": "web01"}},
        "change_type": "update", "changes": {"enforcement_mode": {"from": "visibility_only", "to": "full"}}}])
    label = _event("workload.update", "2026-10-18T09:00:00Z", resource_changes=[{
        "resource": {"workload": {"href": "/orgs/1/workloads/2", "name": "web02"}},
        "change_type": "update", "changes": {"labels": {}}}])
    opaque = _event("workload.update", "2026-10-18T08:00:00Z", resource_changes=[{
        "resource": {"workload": {"href": "/orgs/1/workloads/3"}}, "change_type": "update"}])
    out = _events(_EventsPCE([mode, label, opaque]), {"kind": "enforcement"})
    assert [e["resource_changes"][0]["href"] for e in out["events"]] == [
        "/orgs/1/workloads/1", "/orgs/1/workloads/3"]
    assert out["events"][0]["resource_changes"][0]["name"] == "web01"


def test_pce_failure_is_reported_not_raised():
    class Boom:
        def get(self, *a, **k): raise RuntimeError("503 from the PCE")
    out = _events(Boom(), {})
    assert "error" in out and "503" in out["error"]


# =========================================================================
# get-rulesets timestamps and actors
# =========================================================================

AUDIT = {"created_at": "2026-09-01T08:00:00.000Z", "updated_at": "2026-10-17T16:30:00.000Z",
         "update_type": "update", "created_by": {"href": "/users/1"}, "updated_by": {"href": "/users/2"}}


class _AuditRulesetPCE(_RulesetPCE):
    def __init__(self, rulesets, users=None, **kw):
        super().__init__(rulesets, **kw)
        self._users = users

    def get(self, path, include_org=True, params=None):
        if path == "/users":
            if self._users is None:
                raise RuntimeError("403 not an org owner")
            return NS(json=lambda: self._users)
        return super().get(path)


def _rulesets(pce, args=None):
    out = handle_get_rulesets(ToolContext(pce=pce, is_stdio=True), args or {})
    return json.loads(out[0].text)


def test_rulesets_and_rules_carry_timestamps_and_actor_usernames():
    """Reported: 'when was this rule last changed' could not be answered
    from policy; rulesets and rules had no created_at/updated_at."""
    rs = _ruleset("shop", scopes=[[{"label": {"href": L["app=shop"]}}]],
                  rules=[{**_rule("/r1", [{"actors": "ams"}], [{"label": {"href": L["app=shop"]}}],
                                  [{"port": 443, "proto": 6}]),
                          **AUDIT, "updated_by": {"href": "/users/9"}}])
    rs.update(AUDIT)
    users = [{"href": "/users/1", "username": "alice"}, {"href": "/users/2", "username": "bob"}]
    out = _rulesets(_AuditRulesetPCE([rs], users=users))
    shop = out["rulesets"][0]
    assert shop["created_at"] == AUDIT["created_at"]
    assert shop["updated_at"] == AUDIT["updated_at"]
    assert shop["update_type"] == "update"
    assert shop["created_by"] == {"username": "alice", "href": "/users/1"}
    assert shop["updated_by"] == {"username": "bob", "href": "/users/2"}
    rule = shop["rules"][0]
    assert rule["created_at"] == AUDIT["created_at"] and rule["update_type"] == "update"
    assert rule["created_by"] == {"username": "alice", "href": "/users/1"}
    assert rule["updated_by"] == {"username": None, "href": "/users/9"}      # unknown user


def test_audit_fields_are_omitted_when_the_pce_did_not_send_them():
    out = _rulesets(_AuditRulesetPCE([SHOP], users=[]))
    shop = out["rulesets"][0]
    for key in ("created_at", "updated_at", "update_type", "created_by", "updated_by"):
        assert key not in shop
        assert key not in shop["rules"][0]
    assert shop["href"] and shop["rules"][0]["href"] == "/r1"      # nothing else moved


def test_username_is_null_when_users_cannot_be_listed():
    rs = {**SHOP, **AUDIT}
    shop = _rulesets(_AuditRulesetPCE([rs], users=None))["rulesets"][0]
    assert shop["created_by"] == {"username": None, "href": "/users/1"}
    assert shop["updated_at"] == AUDIT["updated_at"]


def test_a_username_already_in_the_dict_is_used_without_a_lookup():
    rs = {**SHOP, "created_by": {"href": "/users/4", "username": "carol"}}
    pce = _AuditRulesetPCE([rs], users=None)
    assert _rulesets(pce)["rulesets"][0]["created_by"] == {"username": "carol", "href": "/users/4"}


def test_deny_rules_carry_audit_fields_too():
    deny = {"shop": [{"href": "/d1", "enabled": True, "override": False, "description": "",
                      "consumers": [{"actors": "ams"}], "providers": [{"label": {"href": L["app=shop"]}}],
                      "ingress_services": [{"port": 22, "proto": 6}], **AUDIT}]}
    out = _rulesets(_AuditRulesetPCE([SHOP], users=[], deny=deny))
    d = [r for r in out["rulesets"][0]["rules"] if r["rule_type"] == "deny"][0]
    assert d["updated_at"] == AUDIT["updated_at"] and d["created_by"]["href"] == "/users/1"
