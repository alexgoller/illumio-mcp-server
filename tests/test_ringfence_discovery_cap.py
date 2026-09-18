"""Ringfence discovery must not be bounded by the MCP response-size cap.

MCP_BUG_MAX_RESULTS exists to keep a RESPONSE under the client's size limit.
Ringfence discovery returns no flows at all -- it collapses them into a list of
remote app+env pairs -- so applying that cap to the QUERY truncated the very
thing being discovered: a busy app's first 500 flows can be one chatty
neighbour, and every other remote app never appears in the generated ruleset.
"""
import inspect

from illumio_mcp.tools import ringfence
from illumio_mcp.tools.constants import MCP_BUG_MAX_RESULTS


def test_discovery_cap_is_distinct_from_the_response_cap():
    assert ringfence.RINGFENCE_DISCOVERY_MAX_RESULTS > MCP_BUG_MAX_RESULTS, (
        "discovery must pull more flows than the response-size cap allows, "
        "or remote apps are silently dropped from the ruleset"
    )


def test_discovery_queries_do_not_use_the_response_cap():
    """Guards the specific regression: the two discovery queries in
    create-ringfence were built with max_results=MCP_BUG_MAX_RESULTS."""
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "max_results=MCP_BUG_MAX_RESULTS" not in src, (
        "a ringfence discovery query is capped at the response-size limit"
    )
    assert src.count("max_results=RINGFENCE_DISCOVERY_MAX_RESULTS") == 2, (
        "expected both the inbound and outbound discovery queries to use the "
        "discovery cap"
    )


def test_saturation_is_reported_and_reaches_the_dry_run():
    """A dry run is where an incomplete discovery matters most -- it is the
    output a human reviews before provisioning -- so the warning must be
    attached before the dry_run branch returns."""
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "discovery_truncated" in src and "discovery_warning" in src
    assert src.index("discovery_warning") < src.index("if dry_run:"), (
        "the truncation warning is attached after the dry-run return, so the "
        "reviewed output would not carry it"
    )


def test_flows_analysed_is_reported():
    """Callers cannot judge completeness without knowing the sample size."""
    assert "flows_analysed" in inspect.getsource(ringfence.handle_create_ringfence)


# ----- All Services resolution: needed by EVERY ringfence -----

def test_all_services_is_resolved_for_every_ringfence_not_just_selective():
    """The intra-scope and extra-scope ALLOW rules are built from All Services
    too, so gating its lookup on `selective` left all_services_href None on a
    standard ringfence. It fell through to the port -1 fallback and the PCE
    answered `Invalid value -1 - must be integer between 0 and 65535`.

    An earlier version of this test asserted the opposite -- that the lookup
    belonged inside `if selective:` -- and so locked the regression in.
    """
    src = inspect.getsource(ringfence.handle_create_ringfence)
    resolve_at = src.index("resolve_ingress_services(pce, ALL_SERVICES)")
    selective_at = src.index("if selective and explicit_deny_service:")
    assert resolve_at < selective_at, (
        "All Services must be resolved before, and independently of, any "
        "selective-only branch"
    )


def test_all_services_href_comes_from_the_unconditional_lookup():
    """Not from the deny-service result, which a caller can override -- a
    narrowed deny_service must not change what the ALLOW rules cover."""
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "for item in default_services if item.get(\"href\")" in src


def test_explicit_deny_service_is_fatal_but_the_default_is_recoverable():
    """Substituting something broader for a deny the caller named would write
    different policy than asked for. The default has a documented fallback."""
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert '"error": "invalid_deny_service"' in src
    assert "port -1 fallback" in src


def test_deny_service_override_only_applies_to_selective():
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "if selective and explicit_deny_service:" in src


def test_ignored_deny_service_is_reported_not_swallowed():
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "deny_service_ignored" in src, (
        "a deny_service passed without selective=true must be reported, "
        "not silently dropped"
    )
