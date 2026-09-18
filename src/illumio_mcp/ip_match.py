"""Fast IP-to-provider lookup.

Attribution used to scan every range for every flow row. With ~30 ranges that
cost 36 ms per 8,000-row summary, which was invisible. Measured against a real
source list -- Microsoft 365, GCP, selected AWS services -- the range count goes
to a few thousand, and the same linear scan projects to roughly SIX SECONDS per
summary. That would have doubled the cost of the aggregate-first work.

So ranges are bucketed by prefix length. For an address, mask it to each length
that actually appears and look the result up in a dict. That is one dict hit per
distinct prefix length -- typically 10-20 -- no matter how many ranges exist.
Longest prefix wins, so a specific /24 beats the /8 containing it, which is what
makes "this is Microsoft 365 Exchange" beat "this is Microsoft" when both match.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable


class PrefixMatcher:
    """Longest-prefix-match over a set of labelled CIDRs."""

    __slots__ = ("_v4", "_v6", "_lengths4", "_lengths6", "size")

    def __init__(self, entries: Iterable[tuple[str, object]] = ()):
        # {prefix_len: {masked_network_int: payload}}
        self._v4: dict[int, dict[int, object]] = {}
        self._v6: dict[int, dict[int, object]] = {}
        self.size = 0
        for cidr, payload in entries:
            self.add(cidr, payload)
        self._lengths4 = sorted(self._v4, reverse=True)
        self._lengths6 = sorted(self._v6, reverse=True)

    def add(self, cidr: str, payload: object) -> None:
        net = ipaddress.ip_network(cidr, strict=False)
        table = self._v4 if net.version == 4 else self._v6
        bucket = table.setdefault(net.prefixlen, {})
        # First writer wins, so a curated vendor range is not overwritten by a
        # broad cloud range that happens to be loaded later.
        bucket.setdefault(int(net.network_address), payload)
        self.size += 1

    def finalise(self) -> "PrefixMatcher":
        self._lengths4 = sorted(self._v4, reverse=True)
        self._lengths6 = sorted(self._v6, reverse=True)
        return self

    def lookup(self, ip: str):
        """Payload of the most specific matching range, or None."""
        try:
            addr = ipaddress.ip_address(str(ip))
        except (ValueError, TypeError):
            return None

        if addr.version == 4:
            table, lengths, bits = self._v4, self._lengths4, 32
        else:
            table, lengths, bits = self._v6, self._lengths6, 128

        value = int(addr)
        for length in lengths:                 # longest prefix first
            if length == 0:
                masked = 0
            else:
                masked = value & (((1 << length) - 1) << (bits - length))
            hit = table[length].get(masked)
            if hit is not None:
                return hit
        return None
