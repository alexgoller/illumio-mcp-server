"""Service reference resolution and the Windows qualifier rules.

Guards the failure this feature exists to fix: the rule tools rebuilt every
ingress_services entry as {"port", "proto"}, DISCARDING an href the caller had
supplied. The PCE accepted it, stored 0/tcp, and reported success -- a rule that
looks like policy and is not. Everything here is about refusing rather than
guessing, so no test needs a PCE.
"""
import json
import pytest

from illumio_mcp.service_refs import (
    resolve_ingress_services,
    normalise_windows_services,
    coerce_proto,
    lookup_service_by_name,
    ServiceRefError,
    ALL_SERVICES,
)

ALL_SVC_HREF = "/orgs/1/sec_policy/draft/services/99"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


class _Resp:
    def __init__(self, body): self._body = body
    def raise_for_status(self): pass
    def json(self): return self._body


class _PCE:
    """Reproduces the PCE behaviours that matter, including the substring filter."""
    _hostname, org_id = "pce.test", 1
    _ALL = [
        {"name": "All Services", "href": ALL_SVC_HREF},
        {"name": "S-HTTP", "href": "/orgs/1/sec_policy/draft/services/1"},
        {"name": "S-HTTPS", "href": "/orgs/1/sec_policy/draft/services/2"},
        {"name": "S-HTTPS-UDP", "href": "/orgs/1/sec_policy/draft/services/3"},
        {"name": "S-DUP", "href": "/orgs/1/sec_policy/draft/services/4"},
        {"name": "S-DUP", "href": "/orgs/1/sec_policy/draft/services/5"},
        {"name": "S-EGRESS", "href": "/orgs/1/sec_policy/draft/services/6",
         "windows_egress_services": [{"process_name": CHROME}]},
    ]

    def get(self, endpoint, params=None, include_org=False):
        if endpoint.startswith("/orgs/"):
            for s in self._ALL:
                if s["href"] == endpoint:
                    return _Resp(s)
            return _Resp({})
        name = (params or {}).get("name", "")
        # The PCE matches ?name= as a SUBSTRING -- this is the whole reason the
        # exact match has to happen client-side.
        return _Resp([s for s in self._ALL if name in s["name"]])


@pytest.fixture
def pce():
    from illumio_mcp import service_refs
    service_refs._name_cache.clear()
    return _PCE()


# ----- the three reference forms -----

def test_inline_port_unchanged(pce):
    payload, _ = resolve_ingress_services(pce, [{"port": 443, "proto": "tcp"}])
    assert payload == [{"port": 443, "proto": 6}]


def test_href_is_passed_through_untouched(pce):
    payload, _ = resolve_ingress_services(pce, [{"href": ALL_SVC_HREF}])
    assert payload == [{"href": ALL_SVC_HREF}]


def test_service_name_resolves_to_href(pce):
    payload, display = resolve_ingress_services(pce, [{"service": ALL_SERVICES}])
    assert payload == [{"href": ALL_SVC_HREF}]
    assert display[0]["resolved_name"] == ALL_SERVICES


def test_exact_name_wins_over_substring_matches(pce):
    """?name=S-HTTP also returns S-HTTPS and S-HTTPS-UDP on a real PCE."""
    payload, _ = resolve_ingress_services(pce, [{"service": "S-HTTP"}])
    assert payload == [{"href": "/orgs/1/sec_policy/draft/services/1"}]


def test_mixed_inline_and_reference_in_one_list(pce):
    payload, _ = resolve_ingress_services(
        pce, [{"port": 22, "proto": "tcp"}, {"service": ALL_SERVICES}])
    assert payload == [{"port": 22, "proto": 6}, {"href": ALL_SVC_HREF}]


def test_to_port_range_survives(pce):
    payload, _ = resolve_ingress_services(pce, [{"port": 8000, "to_port": 8100, "proto": "tcp"}])
    assert payload == [{"port": 8000, "proto": 6, "to_port": 8100}]


# ----- the silent-strip regression -----

def test_href_beside_port_is_refused_not_silently_dropped(pce):
    """The original bug: href was discarded and the rule stored as 0/tcp."""
    with pytest.raises(ServiceRefError, match="conflicting"):
        resolve_ingress_services(pce, [{"port": 0, "proto": "tcp", "href": ALL_SVC_HREF}])


def test_conflict_message_names_both_fields(pce):
    with pytest.raises(ServiceRefError) as e:
        resolve_ingress_services(pce, [{"port": 0, "proto": "tcp", "href": ALL_SVC_HREF}])
    assert "href" in str(e.value) and "port" in str(e.value)


def test_unknown_key_is_an_error_not_stripped(pce):
    with pytest.raises(ServiceRefError, match="unknown field"):
        resolve_ingress_services(pce, [{"port": 443, "protocol": "tcp"}])


def test_service_and_href_together_refused(pce):
    with pytest.raises(ServiceRefError, match="conflicting"):
        resolve_ingress_services(pce, [{"service": "S-HTTP", "href": ALL_SVC_HREF}])


# ----- unresolvable references stop before the PCE call -----

def test_missing_service_is_an_error(pce):
    with pytest.raises(ServiceRefError, match="not found"):
        resolve_ingress_services(pce, [{"service": "S-NOPE"}])


def test_ambiguous_exact_name_lists_candidates(pce):
    with pytest.raises(ServiceRefError) as e:
        resolve_ingress_services(pce, [{"service": "S-DUP"}])
    assert "ambiguous" in str(e.value) and "services/4" in str(e.value)


def test_empty_list_explains_all_services(pce):
    """The PCE answers [] with ingress_services_cannot_be_empty, which does not
    tell the caller that {'service': 'All Services'} is the fix."""
    with pytest.raises(ServiceRefError) as e:
        resolve_ingress_services(pce, [])
    assert ALL_SERVICES in str(e.value)


def test_port_zero_is_not_advertised_as_all_ports(pce):
    with pytest.raises(ServiceRefError) as e:
        resolve_ingress_services(pce, [])
    assert "does not mean all ports" in str(e.value)


def test_empty_entry_refused(pce):
    with pytest.raises(ServiceRefError, match="empty"):
        resolve_ingress_services(pce, [{}])


# ----- protocol coercion -----

@pytest.mark.parametrize("value,expected", [
    ("tcp", 6), ("TCP", 6), ("udp", 17), ("icmp", 1), (6, 6), (17, 17), ("6", 6)])
def test_proto_forms(value, expected):
    assert coerce_proto(value) == expected


@pytest.mark.parametrize("junk", ["sctp", None, True, [], {}])
def test_bad_proto_refused(junk):
    with pytest.raises(ServiceRefError):
        coerce_proto(junk)


# ----- Windows qualifiers: the PCE's asymmetry -----

def test_ingress_windows_service_accepts_port_and_process():
    out = normalise_windows_services(
        [{"process_name": CHROME, "port": 443, "proto": "tcp"}], "windows_services")
    assert out == [{"process_name": CHROME, "port": 443, "proto": 6}]


def test_egress_accepts_process_only():
    assert normalise_windows_services(
        [{"process_name": CHROME}], "windows_egress_services") == [{"process_name": CHROME}]


def test_egress_rejects_port_with_the_fix_in_the_message():
    """Measured against a live PCE: windows_egress_services takes
    process_name/service_name only and answers a port with a raw schema dump."""
    with pytest.raises(ServiceRefError) as e:
        normalise_windows_services(
            [{"process_name": CHROME, "port": 443}], "windows_egress_services")
    msg = str(e.value)
    assert "does not accept" in msg
    assert "service_ports" in msg, "the error must say where the port belongs"


def test_process_path_is_never_normalised():
    """The VEN matches the path literally. Case-folding or slash rewriting here
    would silently change which binary the rule matches."""
    weird = r"C:\Program Files (x86)\MiXeD CaSe\App.EXE"
    out = normalise_windows_services([{"process_name": weird}], "windows_egress_services")
    assert out[0]["process_name"] == weird


def test_bare_process_name_allowed():
    """A bare name matches that binary in any directory -- wider, but legal."""
    assert normalise_windows_services(
        [{"process_name": "chrome.exe"}], "windows_egress_services")[0]["process_name"] == "chrome.exe"


def test_entry_needs_at_least_one_qualifier():
    with pytest.raises(ServiceRefError, match="at least one"):
        normalise_windows_services([{}], "windows_egress_services")


def test_unknown_windows_key_refused():
    with pytest.raises(ServiceRefError, match="unknown field"):
        normalise_windows_services([{"process_path": CHROME}], "windows_egress_services")


def test_none_is_an_empty_list():
    assert normalise_windows_services(None, "windows_services") == []


# ----- caching -----

def test_name_lookup_is_cached(pce, monkeypatch):
    calls = []
    original = pce.get
    def counting(endpoint, **kw):
        calls.append(endpoint)
        return original(endpoint, **kw)
    monkeypatch.setattr(pce, "get", counting)
    lookup_service_by_name(pce, ALL_SERVICES)
    lookup_service_by_name(pce, ALL_SERVICES)
    assert len([c for c in calls if c == "/sec_policy/draft/services"]) == 1


# ----- scalar convenience form -----

def test_bare_string_is_treated_as_a_service_name(pce):
    """Callers with a scalar default (the ringfence deny service is the string
    'All Services') must not have to wrap it. Not accepting this made every
    selective ringfence fail with invalid_deny_service."""
    payload, display = resolve_ingress_services(pce, ALL_SERVICES)
    assert payload == [{"href": ALL_SVC_HREF}]
    assert display[0]["resolved_name"] == ALL_SERVICES


def test_single_dict_is_accepted_without_a_list(pce):
    payload, _ = resolve_ingress_services(pce, {"service": ALL_SERVICES})
    assert payload == [{"href": ALL_SVC_HREF}]


def test_unknown_bare_string_still_errors(pce):
    with pytest.raises(ServiceRefError, match="not found"):
        resolve_ingress_services(pce, "S-NOPE")
