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


# ----- deny_service resolution must not break the non-selective path -----

def test_deny_service_is_only_resolved_for_selective_ringfences():
    """Only selective mode writes a deny rule.

    Resolving the deny service unconditionally made every ringfence -- plain,
    dry-run, non-selective -- depend on a service lookup it never uses, so a
    transient failure there broke runs that have no deny rule at all.
    """
    src = inspect.getsource(ringfence.handle_create_ringfence)
    resolve_at = src.index("resolve_ingress_services(")
    guard_at = src.index("if selective:")
    assert guard_at < resolve_at, (
        "the deny-service lookup is not inside the `if selective:` branch"
    )


def test_default_deny_service_failure_falls_back_rather_than_erroring():
    """The All Services default is recoverable -- the port -1 fallback predates
    this feature. Only a deny service the caller NAMED is fatal, because
    substituting something broader would silently write different policy."""
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "if explicit_deny_service:" in src
    assert "port -1 fallback" in src


def test_ignored_deny_service_is_reported_not_swallowed():
    src = inspect.getsource(ringfence.handle_create_ringfence)
    assert "deny_service_ignored" in src, (
        "a deny_service passed without selective=true must be reported, "
        "not silently dropped"
    )
