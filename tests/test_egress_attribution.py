"""Destination attribution and process-name normalisation for egress discovery.

The PCE rarely resolves an FQDN for endpoint egress, so a shadow-AI report was
a list of bare IPs. And because process_name is a full path, one binary run by
eight users counted as eight distinct processes -- 20 where the true answer was
"Claude.exe and ChatGPT.exe".
"""
import pytest

from illumio_mcp.tools.traffic import (
    classify_destination,
    process_basename,
    AI_PROVIDER_RANGES,
)


# ----- provider attribution -----

def test_anthropic_range_is_attributed():
    provider, confidence = classify_destination("160.79.104.100")
    assert provider == "anthropic"
    assert confidence == "likely"


def test_cloudflare_fronted_is_not_claimed_as_a_vendor():
    """Several AI providers front on Cloudflare. Naming one would be a guess
    presented as a finding, so this stays explicitly ambiguous."""
    provider, confidence = classify_destination("172.66.0.243")
    assert provider == "cloudflare-fronted"
    assert confidence == "ambiguous"
    assert provider not in ("anthropic", "openai")


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.10", "8.8.8.8"])
def test_unknown_destinations_are_not_guessed(ip):
    assert classify_destination(ip) == (None, None)


@pytest.mark.parametrize("junk", [None, "", "-", "not-an-ip", "999.1.1.1"])
def test_malformed_input_does_not_raise(junk):
    assert classify_destination(junk) == (None, None)


def test_ipv6_is_attributed_not_just_tolerated():
    """The hand-written table was v4-only, so IPv6 egress was invisible. The
    generated table carries Cloudflare's published v6 ranges."""
    assert classify_destination("2606:4700::1111") == ("cloudflare-fronted", "ambiguous")


def test_unknown_ipv6_does_not_raise():
    assert classify_destination("2001:db8::1") == (None, None)


def test_v4_and_v6_are_not_cross_matched():
    """A v4 address must never match a v6 network or vice versa -- the
    containment check compares versions before testing membership."""
    assert classify_destination("2001:db8::1") == (None, None)
    assert classify_destination("192.0.2.1") == (None, None)


def test_provider_ranges_are_compiled_not_strings():
    """Ranges are compiled to network objects once at import. Re-parsing per
    flow row would make attribution the slowest part of a 500-row report."""
    import ipaddress
    for name, _conf, nets in AI_PROVIDER_RANGES:
        assert nets, f"{name} has no ranges"
        for net in nets:
            assert isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network))


def test_ranges_do_not_overlap_across_providers():
    """Overlapping ranges make attribution order-dependent."""
    import ipaddress
    nets = [(name, n) for name, _conf, ns in AI_PROVIDER_RANGES for n in ns]
    for i, (n1, a) in enumerate(nets):
        for n2, b in nets[i + 1:]:
            if n1 != n2:
                assert not a.overlaps(b), f"{n1} {a} overlaps {n2} {b}"


# ----- process basename -----

@pytest.mark.parametrize("raw,expected", [
    (r"C:\Users\hlee\AppData\Local\AnthropicClaude\Claude.exe", "Claude.exe"),
    (r"C:\Program Files\ChatGPT\ChatGPT.exe", "ChatGPT.exe"),
    ("/usr/sbin/httpd", "httpd"),
    ("Claude.exe", "Claude.exe"),
])
def test_basename_strips_user_specific_paths(raw, expected):
    assert process_basename(raw) == expected


def test_two_users_same_binary_collapse_to_one_name():
    """The reason this exists: per-user install paths inflated the distinct
    process count to 20 for a two-process filter."""
    paths = [rf"C:\Users\{u}\AppData\Local\AnthropicClaude\Claude.exe"
             for u in ("hlee", "fpatel", "jdoe")]
    assert len({process_basename(p) for p in paths}) == 1


@pytest.mark.parametrize("junk", [None, "", "-"])
def test_basename_passes_through_sentinels(junk):
    assert process_basename(junk) == junk


def test_shared_infrastructure_is_never_reported_as_a_vendor():
    """20.0.0.0/8 is all of Azure and Cloudflare fronts many sites. Attributing
    either to an AI vendor would tag ordinary business traffic as shadow AI."""
    for ip in ("20.1.2.3", "172.66.0.243", "142.250.1.1"):
        provider, confidence = classify_destination(ip)
        assert confidence == "ambiguous", f"{ip} claimed as {provider}"
        assert provider not in ("anthropic", "openai")


def test_only_vendor_owned_ranges_are_likely():
    assert classify_destination("160.79.104.100")[1] == "likely"


def test_azure_hosted_openai_endpoints_are_not_named_as_openai():
    """RDAP shows 23.102.140.112/28 registered to Microsoft, not OpenAI. It is
    an Azure-hosted OpenAI endpoint, so other tenants can share that space --
    naming OpenAI there would manufacture false positives."""
    provider, confidence = classify_destination("23.102.140.115")
    assert provider == "azure-hosted"
    assert confidence == "ambiguous"


def test_anthropic_range_covers_the_full_rdap_allocation():
    """ARIN allocates 160.79.104.0/21; an earlier hand-written /23 silently
    missed real Claude traffic in the rest of the block."""
    assert classify_destination("160.79.111.5") == ("anthropic", "likely")
