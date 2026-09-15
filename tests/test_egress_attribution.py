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


def test_ipv6_does_not_raise():
    assert classify_destination("2606:4700::1111") == (None, None)


def test_provider_ranges_are_parseable():
    """A typo in a CIDR would silently disable that provider's attribution."""
    import ipaddress
    for name, _conf, cidrs in AI_PROVIDER_RANGES:
        assert cidrs, f"{name} has no ranges"
        for cidr in cidrs:
            ipaddress.ip_network(cidr)  # raises on a malformed entry


def test_ranges_do_not_overlap_across_providers():
    """Overlapping ranges make attribution order-dependent."""
    import ipaddress
    nets = [(name, ipaddress.ip_network(c))
            for name, _conf, cidrs in AI_PROVIDER_RANGES for c in cidrs]
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
    assert classify_destination("23.102.140.115")[1] == "likely"
