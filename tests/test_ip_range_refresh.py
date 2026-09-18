"""The generated attribution table and the guards on its refresh.

No network: these read the committed file and exercise the script's validation
in isolation. The refresh itself runs in CI, never at runtime -- the server
performs no network I/O for attribution, which keeps it deterministic and keeps
customer destination IPs off third-party services.
"""
import importlib.util
import ipaddress
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
DATA = REPO / "src" / "illumio_mcp" / "data" / "ip_ranges.json"


@pytest.fixture(scope="module")
def refresh():
    """Import the script by path; scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location(
        "refresh_ip_ranges", REPO / "scripts" / "refresh_ip_ranges.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def table():
    return json.loads(DATA.read_text())


# ----- the shipped table -----

def test_data_file_is_committed():
    """Runtime falls back to a minimal built-in table when this is absent, so a
    missing file degrades quietly -- worth failing loudly in CI instead."""
    assert DATA.exists(), f"{DATA} missing; run scripts/refresh_ip_ranges.py"


def test_every_cidr_parses(table):
    for entry in table["entries"]:
        assert entry["cidrs"], f"{entry['provider']} has no ranges"
        for cidr in entry["cidrs"]:
            ipaddress.ip_network(cidr)


def test_confidence_is_constrained(table):
    for entry in table["entries"]:
        assert entry["confidence"] in ("likely", "ambiguous")


def test_only_registry_backed_entries_claim_a_vendor(table):
    """`likely` asserts vendor ownership, so it must be backed by RDAP rather
    than by someone's memory. The hand-written table claimed `likely` for three
    ranges RDAP shows registered to Microsoft."""
    for entry in table["entries"]:
        if entry["confidence"] == "likely":
            assert entry["source"] == "rdap", (
                f"{entry['provider']} claims vendor ownership without registry "
                f"backing (source={entry['source']})"
            )
            assert entry.get("registrant")


def test_provenance_is_recorded(table):
    assert table.get("generated_at")
    for entry in table["entries"]:
        assert entry.get("source")


def test_identical_ranges_are_not_claimed_twice(table):
    """Overlap is fine and expected -- lookup is longest-prefix, so Microsoft
    365's /19 correctly beats the coarse Azure /8 containing it. What has no
    winner is two providers claiming the SAME range."""
    seen = {}
    for entry in table["entries"]:
        for cidr in entry["cidrs"]:
            net = ipaddress.ip_network(cidr)
            owner = seen.setdefault(net, entry["provider"])
            assert owner == entry["provider"], (
                f"{net} claimed by both {owner} and {entry['provider']}"
            )


def test_overlaps_resolve_to_the_more_specific_provider(table):
    """The behaviour that replaced the no-overlap rule."""
    from illumio_mcp.ip_match import PrefixMatcher
    m = PrefixMatcher([("20.0.0.0/8", "broad"), ("20.20.32.0/19", "specific")])
    assert m.lookup("20.20.32.5") == "specific"
    assert m.lookup("20.99.1.1") == "broad"


# ----- refresh guards -----

def test_validate_rejects_a_disappearing_provider(refresh):
    """A partial source outage must not silently delete a provider: attribution
    would drop to unknown and the report would look clean rather than broken."""
    problems = []
    refresh._validate(
        [{"provider": "anthropic", "cidrs": ["160.79.104.0/21"]}],
        {"entries": [{"provider": "anthropic"}, {"provider": "cloudflare-fronted"}]},
        problems,
    )
    assert any("cloudflare-fronted" in p and "disappeared" in p for p in problems)


def test_validate_allows_nested_ranges_from_different_providers(refresh):
    """Nesting is how Microsoft 365's /19 lives inside the coarse Azure /8.
    Longest-prefix picks the specific one, which is the desired answer, so this
    must NOT be reported as a problem."""
    problems = []
    refresh._validate(
        [{"provider": "a", "cidrs": ["10.0.0.0/8"]},
         {"provider": "b", "cidrs": ["10.1.0.0/16"]}],
        None, problems,
    )
    assert problems == []


def test_validate_rejects_identical_ranges_from_two_providers(refresh):
    """No 'more specific' exists here, so the answer depends on insertion
    order -- the one overlap case that really is ambiguous."""
    problems = []
    refresh._validate(
        [{"provider": "a", "cidrs": ["10.0.0.0/8"]},
         {"provider": "b", "cidrs": ["10.0.0.0/8"]}],
        None, problems,
    )
    assert any("claimed by both" in p for p in problems)


def test_validate_raises_on_malformed_cidr(refresh):
    with pytest.raises(ValueError):
        refresh._validate([{"provider": "a", "cidrs": ["not-a-cidr"]}], None, [])


def test_rdap_org_mismatch_is_reported_not_silently_accepted(refresh, monkeypatch):
    """If a range is reassigned, we must fail loudly rather than keep
    attributing an unrelated company's traffic to an AI vendor."""
    body = {
        "cidr0_cidrs": [{"v4prefix": "23.102.140.112", "length": 28}],
        "entities": [{"roles": ["registrant"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]]}],
    }
    monkeypatch.setattr(refresh, "_fetch", lambda url: json.dumps(body))
    problems = []
    result = refresh.collect_rdap(
        {"provider": "openai", "confidence": "likely",
         "expect_org": "OpenAI", "seeds": ["23.102.140.113"]}, problems)
    assert result is None, "a reassigned range must not be published"
    assert any("Microsoft" in p and "reassigned" in p for p in problems)


def test_rdap_fetch_failure_does_not_emit_a_partial_entry(refresh, monkeypatch):
    def boom(url):
        raise OSError("network down")
    monkeypatch.setattr(refresh, "_fetch", boom)
    problems = []
    assert refresh.collect_rdap(
        {"provider": "anthropic", "confidence": "likely",
         "expect_org": "Anthropic", "seeds": ["160.79.104.100"]}, problems) is None
    assert any("failed" in p for p in problems)


def test_comparable_ignores_only_the_timestamp(refresh):
    """An unchanged refresh must be a no-op, or CI opens an empty PR weekly."""
    a = {"generated_at": "2026-01-01T00:00:00Z", "entries": [{"provider": "x"}]}
    b = {"generated_at": "2026-06-01T00:00:00Z", "entries": [{"provider": "x"}]}
    c = {"generated_at": "2026-01-01T00:00:00Z", "entries": [{"provider": "y"}]}
    assert refresh._comparable(a) == refresh._comparable(b)
    assert refresh._comparable(a) != refresh._comparable(c)
