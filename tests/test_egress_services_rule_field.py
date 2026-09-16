"""The `egress_services` rule field: the consumer-side process qualifier.

This is the path that makes "browser only into payment" expressible, and it was
the least obvious thing in the feature: the PCE rule model has `egress_services`
but the Illumio SDK's Rule dataclass does not, so it is applied to the rule
rather than passed through Rule.build.

It was verified against a live PCE but had no coverage in the suite, which is
how a field nobody tests quietly stops being sent.
"""
import json
import pytest

from illumio_mcp.tools.sec_rules import handle_update_sec_rule

RULE = "/orgs/1/sec_policy/draft/rule_sets/2/sec_rules/3"
EGRESS_HREF = "/orgs/1/sec_policy/draft/services/6"
PLAIN_HREF = "/orgs/1/sec_policy/draft/services/7"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


class _Resp:
    def __init__(self, body): self._body = body
    def raise_for_status(self): pass
    def json(self): return self._body


class _PCE:
    """Records PUTs so the payload actually sent can be asserted on."""
    _hostname, org_id = "pce.test", 1

    def __init__(self):
        self.puts = []

    def put(self, endpoint, json=None):
        self.puts.append((endpoint, json))
        return _Resp({})

    def get(self, endpoint, params=None, include_org=False):
        if endpoint == EGRESS_HREF:
            return _Resp({"name": "S-VDI-chrome-egress", "href": EGRESS_HREF,
                          "windows_egress_services": [{"process_name": CHROME}]})
        if endpoint == PLAIN_HREF:
            return _Resp({"name": "S-HTTPS", "href": PLAIN_HREF,
                          "service_ports": [{"port": 443, "proto": 6}]})
        if endpoint == RULE:
            return _Resp({"href": RULE, "ingress_services": [{"port": 443, "proto": 6}],
                          "egress_services": [{"href": EGRESS_HREF}], "consumers": []})
        # name lookup
        name = (params or {}).get("name", "")
        pool = [{"name": "S-VDI-chrome-egress", "href": EGRESS_HREF},
                {"name": "S-HTTPS", "href": PLAIN_HREF}]
        return _Resp([s for s in pool if name in s["name"]])


class _Ctx:
    def __init__(self, pce): self.pce = pce


def _call(args, pce=None):
    pce = pce or _PCE()
    from illumio_mcp import service_refs
    service_refs._name_cache.clear()
    return json.loads(handle_update_sec_rule(_Ctx(pce), args)[0].text), pce


# ----- the field is actually sent -----

def test_egress_services_reaches_the_pce_payload():
    _, pce = _call({"href": RULE, "egress_services": [{"service": "S-VDI-chrome-egress"}]})
    assert pce.puts, "nothing was sent"
    _, payload = pce.puts[0]
    assert payload["egress_services"] == [{"href": EGRESS_HREF}]


def test_egress_service_resolves_by_name_like_ingress_does():
    r, _ = _call({"href": RULE, "egress_services": [{"service": "S-VDI-chrome-egress"}]})
    assert r["egress_services_resolved"][0]["resolved_name"] == "S-VDI-chrome-egress"


def test_egress_accepts_a_bare_href():
    _, pce = _call({"href": RULE, "egress_services": [{"href": EGRESS_HREF}]})
    assert pce.puts[0][1]["egress_services"] == [{"href": EGRESS_HREF}]


def test_ingress_and_egress_are_sent_together_not_merged():
    """The whole point: port on the provider side, process on the consumer
    side, in ONE rule. Collapsing them into one field loses the qualifier."""
    _, pce = _call({"href": RULE,
                    "ingress_services": [{"port": 443, "proto": "tcp"}],
                    "egress_services": [{"service": "S-VDI-chrome-egress"}]})
    payload = pce.puts[0][1]
    assert payload["ingress_services"] == [{"port": 443, "proto": 6}]
    assert payload["egress_services"] == [{"href": EGRESS_HREF}]


def test_egress_alone_does_not_clear_ingress():
    """Only supplied fields change -- sending egress must not blank the ports."""
    _, pce = _call({"href": RULE, "egress_services": [{"href": EGRESS_HREF}]})
    assert "ingress_services" not in pce.puts[0][1]


def test_egress_is_listed_in_updated_fields():
    r, _ = _call({"href": RULE, "egress_services": [{"href": EGRESS_HREF}]})
    assert "egress_services" in r["updated_fields"]


# ----- failure modes -----

def test_unresolvable_egress_service_writes_nothing():
    r, pce = _call({"href": RULE, "egress_services": [{"service": "S-NOPE"}]})
    assert r["error"] == "invalid_egress_services"
    assert not pce.puts, "a bad egress reference must not reach the PCE"


def test_conflicting_keys_in_egress_entry_refused():
    r, pce = _call({"href": RULE,
                    "egress_services": [{"port": 443, "href": EGRESS_HREF}]})
    assert r["error"] == "invalid_egress_services"
    assert not pce.puts


def test_egress_service_in_ingress_is_refused_and_writes_nothing():
    """The PCE answers ingress_service_cannot_be_windows_egress_service without
    saying where the service belongs."""
    r, pce = _call({"href": RULE, "ingress_services": [{"href": EGRESS_HREF}]})
    assert r["error"] == "egress_service_in_ingress"
    assert "egress_services" in r["message"]
    assert not pce.puts


def test_a_plain_service_in_ingress_is_still_allowed():
    """The guard must not reject ordinary service objects."""
    r, pce = _call({"href": RULE, "ingress_services": [{"service": "S-HTTPS"}]})
    assert "error" not in r
    assert pce.puts[0][1]["ingress_services"] == [{"href": PLAIN_HREF}]


# ----- schema advertises it -----

@pytest.mark.parametrize("tool_name", ["update-sec-rule", "create-ruleset"])
def test_egress_services_is_advertised(tool_name):
    import asyncio
    from illumio_mcp.server import handle_list_tools
    tools = {t.name: t for t in asyncio.run(handle_list_tools())}
    schema = tools[tool_name].inputSchema["properties"]
    if tool_name == "create-ruleset":
        schema = schema["rules"]["items"]["properties"]
    assert "egress_services" in schema
    assert "consumer" in schema["egress_services"]["description"].lower()


# ----- create-ruleset applies egress after the SDK creates the rule -----

def test_create_ruleset_applies_egress_services_after_create():
    """The SDK's Rule dataclass has no egress_services field, so Rule.build
    cannot carry it -- create-ruleset must PUT it onto the created rule.

    A source guard rather than a behavioural one: faking the whole ruleset
    creation path (labels, scopes, SDK Rule objects) would test the fake more
    than the code. The behaviour itself was verified against a live PCE.
    """
    import inspect
    from illumio_mcp.tools import rulesets

    src = inspect.getsource(rulesets.handle_create_ruleset)
    create_at = src.index("pce.rules.create(")
    put_at = src.index('"egress_services": egress_payload')
    assert create_at < put_at, (
        "egress_services must be applied AFTER the rule exists; the SDK cannot "
        "carry the field through Rule.build"
    )
    assert "if egress_payload:" in src, "the extra PUT must be conditional"


def test_create_ruleset_resolves_egress_before_creating_anything():
    """An unresolvable egress reference must not leave a half-built ruleset."""
    import inspect
    from illumio_mcp.tools import rulesets

    src = inspect.getsource(rulesets.handle_create_ruleset)
    resolve_at = src.index('rule_def["egress_services"]')
    create_at = src.index("pce.rules.create(")
    assert resolve_at < create_at, (
        "egress references are resolved after the rule is created, so a bad "
        "reference would leave the rule written without its qualifier"
    )


def test_sdk_rule_still_lacks_egress_services():
    """If a future SDK adds the field, the extra PUT can be dropped -- this
    test is the reminder to check."""
    import dataclasses
    from illumio.rules import Rule
    fields = {f.name for f in dataclasses.fields(Rule)}
    assert "egress_services" not in fields, (
        "the SDK now models egress_services; create-ruleset's extra PUT can "
        "probably be replaced with Rule.build(egress_services=...)"
    )
