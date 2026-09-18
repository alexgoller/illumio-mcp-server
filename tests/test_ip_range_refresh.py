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


# Address space that identifies a PLATFORM rather than a tenant. None of these
# may ever claim `likely`, whoever publishes the list.
SHARED_INFRASTRUCTURE = {
    "cloudflare-fronted", "fastly", "azure-hosted", "google-cloud",
    "google-services", "microsoft365", "microsoft365-exchange",
    "microsoft365-sharepoint", "microsoft365-skype",
}


def test_likely_entries_have_real_provenance(table):
    """`likely` asserts vendor ownership, so it needs a source -- RDAP, or the
    vendor's own published range file. It must never rest on someone's memory:
    the original hand-written table claimed `likely` for three ranges RDAP shows
    registered to Microsoft."""
    for entry in table["entries"]:
        if entry["confidence"] != "likely":
            continue
        if entry["source"] == "rdap":
            assert entry.get("registrant"), f"{entry['provider']}: no registrant"
        else:
            assert entry["source"] == "published", entry["provider"]
            assert entry.get("source_urls"), (
                f"{entry['provider']} claims vendor ownership with no source URL"
            )


def test_shared_infrastructure_never_claims_a_vendor(table):
    """A CDN or cloud range identifies the platform, never whose tenant it is."""
    for entry in table["entries"]:
        if entry["provider"] in SHARED_INFRASTRUCTURE or entry["provider"].startswith("aws-"):
            assert entry["confidence"] == "ambiguous", (
                f"{entry['provider']} must stay ambiguous: the address belongs to "
                f"the platform, and thousands of unrelated tenants share it"
            )


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


# ----- SaaS coverage: what is attributable, and what provably is not -----

def test_saas_providers_are_present(table):
    """The vendors people actually ask about, each from its own published list
    or from RDAP."""
    providers = {e["provider"] for e in table["entries"]}
    for expected in ("salesforce", "workday", "zoom", "google-services",
                     "microsoft365-exchange", "github", "atlassian",
                     "dropbox", "box"):
        assert expected in providers, f"{expected} missing from the table"


def test_vendor_owned_space_is_likely_and_shared_infra_is_not():
    """Confidence must track who owns the address, not who is popular."""
    from illumio_mcp.tools.traffic import classify_destination
    assert classify_destination("209.177.165.18")[1] == "likely"      # Workday's own
    assert classify_destination("170.114.52.2")[1] == "likely"        # Zoom's own
    for shared in ("172.66.0.243",):                                  # Cloudflare edge
        assert classify_destination(shared)[1] == "ambiguous"


def test_google_services_is_not_the_same_as_google_cloud(table):
    """goog.json minus cloud.json: Gmail and Workspace, as opposed to someone's
    VM in GCP. Keeping both unsubtracted put identical ranges in two providers,
    the one overlap longest-prefix cannot arbitrate."""
    by = {e["provider"]: set(e["cidrs"]) for e in table["entries"]}
    assert "google-services" in by and "google-cloud" in by
    assert not (by["google-services"] & by["google-cloud"])


def test_cdn_fronted_saas_are_not_falsely_claimed(table):
    """Slack, Zendesk, DocuSign and ServiceNow do not own the addresses they
    answer on. Claiming them would attribute a CDN's whole tenant base to one
    vendor."""
    providers = {e["provider"] for e in table["entries"]}
    for impossible in ("slack", "zendesk", "docusign", "servicenow"):
        assert impossible not in providers, (
            f"{impossible} is CDN-fronted; no IP range can attribute it"
        )


def test_github_actions_bulk_is_excluded(table):
    """`actions` alone is ~6,500 runner-egress prefixes meaning 'a CI runner
    phoned home', not 'someone used GitHub'. GitHub is also ONE provider, not
    one per key: web, git and api are served from the same ranges, so splitting
    them would imply a separation that does not exist."""
    providers = {e["provider"] for e in table["entries"]}
    assert "github-actions" not in providers
    assert not any(p.startswith("github-") for p in providers)
    gh = sum(len(e["cidrs"]) for e in table["entries"] if e["provider"].startswith("github"))
    assert gh < 500, f"github ranges ballooned to {gh}"


def test_table_stays_within_a_sane_size(table):
    """Attribution is bundled package data; it should stay in the low
    thousands. AWS alone publishes 17,521 prefixes, most meaning 'somewhere in
    AWS'."""
    total = sum(len(e["cidrs"]) for e in table["entries"])
    assert total < 8000, f"{total} ranges is more than this should carry"
