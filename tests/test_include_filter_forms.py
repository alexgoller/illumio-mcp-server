"""Every string form the Explorer API accepts survives nesting (#47).

`include_*` filters are nested into one AND-block before TrafficQuery.build.
The SDK parses filter strings only at the top level of the include list, so a
nested "10.0.0.5" reached validation raw and failed with "Invalid value for
include: [['10.0.0.5']]". Labels had been worked around; IPs, IP-list and
workload HREFs, FQDNs and transmission types had not. No PCE required:
TrafficQuery.build validates without a network, so these assert what the SDK
accepts rather than what the helpers return.
"""
import json

import pytest
from illumio import TrafficQuery

from illumio_mcp.context import ToolContext
from illumio_mcp.tools.traffic import (
    FilterProblems,
    _normalise_filter,
    _resolve_filter_block,
    _resolve_label_filters,
    _unresolved_error,
    handle_get_traffic_flows,
    handle_get_traffic_flows_summary,
    handle_get_traffic_timeline,
    handle_discover_process_egress,
)
from illumio_mcp.tools.identity import handle_build_identity_graph


IP_LIST = "/orgs/1/sec_policy/draft/ip_lists/1"
WORKLOAD = "/orgs/1/workloads/8d9c6b2e-2b7e-4d0e-9a2f-5c1b3a4d5e6f"
APP_HREF = "/orgs/1/labels/48"


def _build(**kwargs):
    args = dict(start_date="2026-10-01", end_date="2026-10-02",
                include_sources=[[]], include_destinations=[[]],
                exclude_sources=[], exclude_destinations=[],
                include_services=[], exclude_services=[], policy_decisions=[],
                max_results=10, query_name="contract-test")
    args.update(kwargs)
    return TrafficQuery.build(**args)


def _resolve(arguments):
    """Resolve the way the handlers do, with a PCE that is never consulted."""
    class _NoPCE:
        labels = None
    return _resolve_label_filters(_NoPCE(), arguments)


# --- each form, serialised through the SDK --------------------------------

def test_include_sources_ip_serialises_to_an_ip_address_filter():
    """The repro from #47."""
    args = {"include_sources": ["10.0.0.5"]}
    assert not _resolve(args)
    query = _build(include_sources=_normalise_filter(args["include_sources"]))
    assert query.sources.include == [[{"ip_address": "10.0.0.5"}]]


def test_ipv6_is_an_ip_address_too():
    """The SDK's own parser uses inet_aton, which is IPv4-only."""
    assert _resolve_filter_block(["2001:db8::5"], {}, []) == [{"ip_address": "2001:db8::5"}]


def test_ip_list_href_becomes_an_ip_list_filter():
    """The Explorer idiom for "endpoints that are not workloads": include an
    Any IP list with exclude_workloads_from_ip_list_query=true."""
    args = {"include_sources": [IP_LIST]}
    _resolve(args)
    query = _build(include_sources=_normalise_filter(args["include_sources"]))
    assert query.sources.include == [[{"ip_list": {"href": IP_LIST}}]]


def test_workload_href_becomes_a_workload_filter():
    args = {"include_destinations": [WORKLOAD]}
    _resolve(args)
    query = _build(include_destinations=_normalise_filter(args["include_destinations"]))
    assert query.destinations.include == [[{"workload": {"href": WORKLOAD}}]]


def test_fqdn_on_destinations_becomes_an_fqdn_filter():
    args = {"include_destinations": ["api.example.com"]}
    assert not _resolve(args)
    query = _build(include_destinations=_normalise_filter(args["include_destinations"]))
    assert query.destinations.include == [[{"fqdn": "api.example.com"}]]


@pytest.mark.parametrize("kind", ["broadcast", "multicast", "unicast"])
def test_transmission_on_destinations_becomes_a_transmission_filter(kind):
    args = {"include_destinations": [kind]}
    assert not _resolve(args)
    query = _build(include_destinations=_normalise_filter(args["include_destinations"]))
    assert query.destinations.include == [[{"transmission": kind}]]


def test_mixed_label_and_ip_land_in_one_and_block():
    conditions = _resolve_filter_block(["app=vdi", "10.0.0.5", IP_LIST],
                                       {"app=vdi": APP_HREF}, [])
    query = _build(include_sources=_normalise_filter(conditions))
    assert query.sources.include == [[
        {"label": {"href": APP_HREF}}, {"ip_address": "10.0.0.5"},
        {"ip_list": {"href": IP_LIST}},
    ]], "one block means AND; separate blocks would silently OR them"


def test_label_href_is_still_a_label_filter():
    assert _resolve_filter_block([APP_HREF], {}, []) == [{"label": {"href": APP_HREF}}]


def test_dicts_and_unknown_strings_pass_through():
    """A pre-built filter dict, and a string no form claims, are not rewritten."""
    assert _resolve_filter_block([{"ip_list": {"href": IP_LIST}}], {}, []) == \
        [{"ip_list": {"href": IP_LIST}}]
    assert _resolve_filter_block(["/orgs/1/virtual_services/9"], {}, []) == \
        ["/orgs/1/virtual_services/9"]


# --- the exclude side is passed flat and must keep working ----------------

def test_exclude_filters_stay_flat_and_resolve():
    args = {"exclude_sources": ["10.0.0.9", IP_LIST],
            "exclude_destinations": ["api.example.com", "broadcast"]}
    assert not _resolve(args)
    query = _build(exclude_sources=args["exclude_sources"],
                   exclude_destinations=args["exclude_destinations"])
    assert query.sources.exclude == [{"ip_address": "10.0.0.9"},
                                     {"ip_list": {"href": IP_LIST}}]
    assert query.destinations.exclude == [{"fqdn": "api.example.com"},
                                          {"transmission": "broadcast"}]


# --- destination-only forms on the source side are an error, not a 400 ----

def test_fqdn_on_sources_is_reported_before_the_query_is_sent():
    args = {"include_sources": ["api.example.com"]}
    problems = _resolve(args)
    assert problems.source_only == ["api.example.com"]
    assert args["include_sources"] == ["api.example.com"], "left as given, not converted"
    err = _unresolved_error(problems, None)
    assert err["error"] == "unsupported_source_filter"
    assert err["unsupported"] == ["api.example.com"]
    assert "include_destinations" in err["message"]


def test_transmission_on_exclude_sources_is_reported_too():
    args = {"exclude_sources": ["multicast"]}
    assert _resolve(args).source_only == ["multicast"]


def test_no_problems_means_no_error():
    assert _unresolved_error(FilterProblems(), None) is None


# --- every handler that takes these filters fails fast the same way -------

class _UntouchedPCE:
    """Any attribute access is a bug: the handler must stop before querying."""
    def __getattr__(self, name):
        raise AssertionError(f"PCE was consulted ({name}) despite an invalid filter")


@pytest.mark.parametrize("handler, extra", [
    (handle_get_traffic_flows, {}),
    (handle_get_traffic_flows_summary, {}),
    (handle_get_traffic_timeline, {"bucket": "1d"}),
    (handle_discover_process_egress, {}),
    (handle_build_identity_graph, {}),
])
def test_handlers_return_the_structured_error_for_a_source_fqdn(handler, extra):
    args = {"start_date": "2026-10-01", "end_date": "2026-10-02",
            "include_sources": ["api.example.com"], **extra}
    out = json.loads(handler(ToolContext(pce=_UntouchedPCE(), is_stdio=True), args)[0].text)
    assert out["error"] == "unsupported_source_filter", out
    assert out["unsupported"] == ["api.example.com"]
