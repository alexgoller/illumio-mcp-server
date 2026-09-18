"""Longest-prefix matcher behind destination attribution.

Attribution scanned every range for every flow row. At ~30 ranges that was
36 ms per 8,000-row summary. Measured against the real published sources --
Microsoft 365, GCP, selected AWS services -- the range count reaches ~2,900,
and the same scan projected to roughly six seconds, which would have doubled
the cost of the aggregate-first work. Bucketing by prefix length makes lookup
independent of range count.
"""
import ipaddress
import time

import pytest

from illumio_mcp.ip_match import PrefixMatcher


def test_longest_prefix_wins():
    """The property the whole design rests on: 'Microsoft 365 Exchange' must
    beat 'somewhere in Azure' when both ranges contain the address."""
    m = PrefixMatcher([("20.0.0.0/8", "azure"), ("20.20.32.0/19", "m365")])
    assert m.lookup("20.20.32.5") == "m365"
    assert m.lookup("20.99.1.1") == "azure"


def test_three_levels_of_nesting():
    m = PrefixMatcher([("10.0.0.0/8", "a"), ("10.1.0.0/16", "b"), ("10.1.2.0/24", "c")])
    assert [m.lookup(ip) for ip in ("10.1.2.3", "10.1.9.9", "10.9.9.9", "11.0.0.1")] \
        == ["c", "b", "a", None]


def test_no_match_returns_none():
    m = PrefixMatcher([("10.0.0.0/8", "a")])
    assert m.lookup("8.8.8.8") is None


@pytest.mark.parametrize("junk", ["", None, "nonsense", "999.1.1.1", "10.0.0.0/8"])
def test_malformed_input_never_raises(junk):
    assert PrefixMatcher([("10.0.0.0/8", "a")]).lookup(junk) is None


# ----- address families must not cross -----

def test_v4_and_v6_are_separate():
    m = PrefixMatcher([("0.0.0.0/0", "v4-default"), ("2606:4700::/32", "cloudflare-v6")])
    assert m.lookup("1.2.3.4") == "v4-default"
    assert m.lookup("2606:4700::1111") == "cloudflare-v6"
    assert m.lookup("2001:db8::1") is None


def test_v6_longest_prefix():
    m = PrefixMatcher([("2606:4700::/32", "broad"), ("2606:4700:4400::/48", "specific")])
    assert m.lookup("2606:4700:4400::1") == "specific"
    assert m.lookup("2606:4700:9999::1") == "broad"


def test_default_route_is_handled():
    """A /0 masks to zero; the shift arithmetic has a special case for it."""
    assert PrefixMatcher([("0.0.0.0/0", "everything")]).lookup("203.0.113.9") == "everything"


# ----- duplicate handling -----

def test_first_writer_wins_for_identical_ranges():
    """So a curated vendor range is not overwritten by a broad cloud range
    loaded afterwards."""
    m = PrefixMatcher([("10.0.0.0/8", "curated"), ("10.0.0.0/8", "bulk")])
    assert m.lookup("10.1.1.1") == "curated"


def test_host_bits_are_tolerated():
    """Published lists are not always strictly masked."""
    m = PrefixMatcher([("10.1.2.3/24", "x")])
    assert m.lookup("10.1.2.99") == "x"


# ----- the performance claim, asserted rather than assumed -----

def test_lookup_cost_is_independent_of_range_count():
    """The reason this class exists. A linear scan would be ~100x slower at
    5,000 ranges; this must stay flat."""
    import random
    random.seed(11)
    entries = [(f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.0/24",
                f"p{i}") for i in range(5000)]
    big = PrefixMatcher(entries)
    small = PrefixMatcher(entries[:20])
    ips = [f"104.{i % 255}.{(i * 7) % 255}.{(i * 13) % 255}" for i in range(4000)]

    def elapsed(matcher):
        t0 = time.perf_counter()
        for ip in ips:
            matcher.lookup(ip)
        return time.perf_counter() - t0

    big_t, small_t = elapsed(big), elapsed(small)
    assert big_t < small_t * 8, (
        f"250x the ranges cost {big_t / max(small_t, 1e-9):.1f}x the time; "
        f"lookup is no longer independent of range count"
    )


def test_size_counts_every_range():
    m = PrefixMatcher([("10.0.0.0/8", "a"), ("2606:4700::/32", "b")])
    assert m.size == 2


# ----- the shipped table -----

def test_shipped_table_is_loaded_into_a_matcher():
    from illumio_mcp.tools.traffic import _PROVIDER_MATCHER
    assert _PROVIDER_MATCHER.size > 100, "expected the expanded published sources"


def test_shipped_table_still_attributes_known_addresses():
    from illumio_mcp.tools.traffic import classify_destination
    assert classify_destination("160.79.104.100") == ("anthropic", "likely")
    assert classify_destination("192.0.2.1") == (None, None)
