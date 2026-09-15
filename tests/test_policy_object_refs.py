"""Reference encoding for policy objects. No PCE required.

Both bugs here shared a shape: a malformed reference that the PCE either
rejects with a brace-wrapped echo (406 invalid_uri) or, worse, silently
accepts in a WIDER form than was asked for.
"""
import json

import pytest

from illumio_mcp.tools.deny_rules import _actor_reference


IP_LIST = "/orgs/5636114/sec_policy/draft/ip_lists/24206847997116452"
LABEL = "/orgs/5636114/labels/24206847997120568"
WORKLOAD = "/orgs/5636114/workloads/abc-123"


class FakeIPList:
    def __init__(self, href): self.href = href


class FakeIPLists:
    def __init__(self, byname): self._byname = byname
    def get(self, params=None):
        name = (params or {}).get("name")
        return [FakeIPList(self._byname[name])] if name in self._byname else []


class FakePCE:
    def __init__(self, ip_lists=None):
        self.ip_lists = FakeIPLists(ip_lists or {})


VALUES = {"app=vdi": LABEL}


# --- the 406 bug -----------------------------------------------------------

def test_bare_ip_list_href_becomes_an_ip_list_reference():
    """Regression: the catch-all assumed every unrecognised string was a label
    href, so an IP-list href became {"label": {"href": ...}} and the PCE
    answered 406 invalid_uri: {{"href"=>"/orgs/.../ip_lists/..."}}."""
    actor, err = _actor_reference(IP_LIST, FakePCE(), VALUES, "provider")
    assert err is None
    assert actor == {"ip_list": {"href": IP_LIST}}


def test_bare_label_href_still_becomes_a_label_reference():
    actor, err = _actor_reference(LABEL, FakePCE(), VALUES, "provider")
    assert err is None and actor == {"label": {"href": LABEL}}


def test_workload_href_is_dispatched_by_path_segment():
    actor, err = _actor_reference(WORKLOAD, FakePCE(), VALUES, "consumer")
    assert err is None and actor == {"workload": {"href": WORKLOAD}}


def test_unknown_href_type_is_an_error_not_a_guess():
    """Guessing 'label' is what produced the 406. Say so instead."""
    actor, err = _actor_reference("/orgs/1/sec_policy/draft/services/9",
                                  FakePCE(), VALUES, "provider")
    assert actor is None
    assert "Unrecognised provider HREF" in err


def test_iplist_by_name_still_works():
    pce = FakePCE({"Any (0.0.0.0/0 and ::/0)": IP_LIST})
    actor, err = _actor_reference("iplist:Any (0.0.0.0/0 and ::/0)", pce, VALUES, "provider")
    assert err is None and actor == {"ip_list": {"href": IP_LIST}}


def test_missing_iplist_name_is_reported():
    actor, err = _actor_reference("iplist:Nope", FakePCE(), VALUES, "provider")
    assert actor is None and "IP list not found" in err


def test_label_shorthand_and_ams_are_unchanged():
    assert _actor_reference("app=vdi", FakePCE(), VALUES, "consumer")[0] == \
        {"label": {"href": LABEL}}
    assert _actor_reference("ams", FakePCE(), VALUES, "consumer")[0] == {"actors": "ams"}


def test_nonsense_reference_is_rejected():
    actor, err = _actor_reference("banana", FakePCE(), VALUES, "provider")
    assert actor is None and "Unrecognised provider reference" in err


# --- the silent-widening bug ----------------------------------------------

def test_both_ruleset_handlers_accept_key_value_scopes():
    """{"key": "app", "value": "vdi"} previously fell through a catch-all that
    logged a warning and continued, producing an EMPTY scope -- the ruleset was
    created unscoped and the caller was told nothing. Source guard, because the
    handler needs a live PCE to run."""
    import pathlib
    src = pathlib.Path("src/illumio_mcp/tools/rulesets.py").read_text()
    assert src.count('elif isinstance(label, dict) and "key" in label and "value" in label:') == 2, \
        "both create-ruleset and update-ruleset must accept {key, value} scopes"


def test_unknown_scope_label_is_never_skipped_silently():
    """A dropped scope label makes the ruleset WIDER than asked for, which is
    the dangerous direction for a policy object."""
    import pathlib
    src = pathlib.Path("src/illumio_mcp/tools/rulesets.py").read_text()
    assert 'logger.warning(f"Unexpected label format' not in src, \
        "unrecognised scope labels must return an error, not be skipped"
    assert '"error": "invalid_scope_label"' in src
