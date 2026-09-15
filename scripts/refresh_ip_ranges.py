#!/usr/bin/env python3
"""Refresh the destination-attribution IP ranges from authoritative sources.

Runs in CI, never at runtime. The MCP server itself performs no network I/O for
attribution: it reads the generated JSON and does offline CIDR containment. That
keeps the server deterministic, keeps customer destination IPs from being sent
to a third party, and keeps it deployable in restricted-egress environments.

What this actually solves is ROT. A hand-written range table is correct the day
it is written and silently wrong later, with nothing to detect the drift. Here
every claim is re-derived from a registry or a vendor-published file, and a
change arrives as a reviewable diff.

Two source kinds:

  RDAP   For vendor-owned space. Look up a seed IP, take the registry's own
         netblock and registrant org. This is ground truth, not a guess. On its
         first run it caught two errors in the hand-written table it replaced:
         the Anthropic entry was /23 where ARIN says /21 (missing real Claude
         traffic), and three ranges labelled "openai" with high confidence are
         registered to Microsoft -- Azure-hosted OpenAI endpoints, shared with
         other tenants.

  Published lists  For shared infrastructure that publishes machine-readable
         ranges (Cloudflare). Fetched wholesale.

Deliberately NOT collected: reverse DNS. Measured against a live Anthropic IP,
160.79.104.100 has PTR fatpipe.juilliard.edu -- stale third-party data that
would have reported Claude traffic as going to Juilliard. Confidently wrong is
worse than a bare IP.

Usage:  python scripts/refresh_ip_ranges.py [--check]
        --check verifies the committed file is current without writing (CI).
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import pathlib
import sys
import urllib.error
import urllib.request

OUTPUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "illumio_mcp" / "data" / "ip_ranges.json"

USER_AGENT = "illumio-mcp-server ip-range refresh (+https://github.com/alexgoller/illumio-mcp-server)"
TIMEOUT = 30

# Vendor-owned space, resolved via RDAP from a seed IP.
#
# `expect_org` is asserted, not assumed: if a range is reassigned to someone
# else, we must fail loudly rather than keep attributing another company's
# traffic to an AI vendor. Seeds are addresses observed in real flow data.
RDAP_SEEDS = [
    {"provider": "anthropic", "confidence": "likely",
     "expect_org": "Anthropic", "seeds": ["160.79.104.100"]},
]

# Shared infrastructure that publishes its own ranges. A hit here narrows the
# field but does NOT name a vendor -- Anthropic and OpenAI both front on
# Cloudflare -- so these stay `ambiguous` no matter how authoritative the source.
PUBLISHED_LISTS = [
    {"provider": "cloudflare-fronted", "confidence": "ambiguous",
     "urls": ["https://www.cloudflare.com/ips-v4",
              "https://www.cloudflare.com/ips-v6"],
     "format": "lines"},
]

# Coarse cloud ranges kept by hand, on purpose. 20.0.0.0/8 is the whole of
# Azure; the precise service-tag list is tens of megabytes and would not make
# the answer any more useful, because the claim these support is only "hosted
# on this cloud", never "is an AI service". Marked ambiguous for that reason.
STATIC_ENTRIES = [
    # The three /28s below shipped as provider "openai" with confidence
    # "likely". RDAP says otherwise: 23.102.140.113 is registered to Microsoft
    # Corporation, not OpenAI. They are OpenAI's Azure-hosted endpoints, which
    # means other Azure tenants can share that space -- so naming OpenAI was a
    # false-positive generator of exactly the kind this table is supposed to
    # avoid. Kept, because dropping them would lose real signal, but demoted to
    # what the registry actually supports: hosted on Azure, vendor unproven.
    {"provider": "azure-hosted", "confidence": "ambiguous",
     "cidrs": ["20.0.0.0/8", "23.102.140.112/28", "13.66.11.96/28",
               "104.210.133.240/28"],
     "source": "curated:coarse-cloud"},
    {"provider": "google-hosted", "confidence": "ambiguous",
     "cidrs": ["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19"],
     "source": "curated:coarse-cloud"},
]


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/rdap+json, application/json, text/plain",
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8")


def _rdap_org(body: dict) -> str | None:
    """Registrant organisation name from an RDAP response."""
    for entity in body.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrant" not in roles and "administrative" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if not (isinstance(vcard, list) and len(vcard) > 1):
            continue
        for field in vcard[1]:
            if isinstance(field, list) and len(field) > 3 and field[0] == "fn":
                return str(field[3])
    return None


def _rdap_cidrs(body: dict) -> list[str]:
    out = []
    for c in body.get("cidr0_cidrs") or []:
        prefix = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if prefix and length is not None:
            out.append(f"{prefix}/{length}")
    return out


def collect_rdap(spec: dict, problems: list) -> dict | None:
    cidrs: set[str] = set()
    sources: set[str] = set()
    for seed in spec["seeds"]:
        url = f"https://rdap.org/ip/{seed}"
        try:
            body = json.loads(_fetch(url))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
            problems.append(f"{spec['provider']}: RDAP fetch failed for {seed}: {e}")
            continue

        org = _rdap_org(body) or ""
        if spec["expect_org"].lower() not in org.lower():
            # Loud, not silent: a reassigned range means we would otherwise keep
            # attributing an unrelated company's traffic to an AI vendor.
            problems.append(
                f"{spec['provider']}: seed {seed} now registered to {org!r}, "
                f"expected {spec['expect_org']!r} -- range reassigned?"
            )
            continue

        found = _rdap_cidrs(body)
        if not found:
            problems.append(f"{spec['provider']}: RDAP returned no CIDR for {seed}")
            continue
        cidrs.update(found)
        sources.add(url)

    if not cidrs:
        return None
    return {
        "provider": spec["provider"],
        "confidence": spec["confidence"],
        "cidrs": sorted(cidrs, key=_cidr_sort_key),
        "source": "rdap",
        "source_urls": sorted(sources),
        "registrant": spec["expect_org"],
    }


def collect_published(spec: dict, problems: list) -> dict | None:
    cidrs: set[str] = set()
    ok_urls: list[str] = []
    for url in spec["urls"]:
        try:
            text = _fetch(url)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            problems.append(f"{spec['provider']}: fetch failed for {url}: {e}")
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ipaddress.ip_network(line)
            except ValueError:
                problems.append(f"{spec['provider']}: unparseable entry {line!r} from {url}")
                continue
            cidrs.add(line)
        ok_urls.append(url)

    if not cidrs:
        return None
    return {
        "provider": spec["provider"],
        "confidence": spec["confidence"],
        "cidrs": sorted(cidrs, key=_cidr_sort_key),
        "source": "published",
        "source_urls": ok_urls,
    }


def _cidr_sort_key(cidr: str):
    net = ipaddress.ip_network(cidr)
    return (net.version, int(net.network_address), net.prefixlen)


def _validate(entries: list[dict], previous: dict | None, problems: list) -> None:
    """Refuse to ship a table that is worse than the one already committed.

    A partial outage must not quietly delete a provider: attribution would drop
    to "unknown" for that vendor and the report would look clean rather than
    broken.
    """
    for entry in entries:
        for cidr in entry["cidrs"]:
            ipaddress.ip_network(cidr)  # raises on malformed

    nets = [(e["provider"], ipaddress.ip_network(c))
            for e in entries for c in e["cidrs"]]
    for i, (p1, a) in enumerate(nets):
        for p2, b in nets[i + 1:]:
            if p1 != p2 and a.overlaps(b):
                problems.append(
                    f"overlap between {p1} {a} and {p2} {b} -- attribution would "
                    f"depend on table order"
                )

    if previous:
        had = {e["provider"] for e in previous.get("entries", [])}
        now = {e["provider"] for e in entries}
        for gone in sorted(had - now):
            problems.append(f"provider {gone} disappeared from the refreshed table")


def build(problems: list, previous: dict | None) -> dict:
    entries: list[dict] = []
    for spec in RDAP_SEEDS:
        entry = collect_rdap(spec, problems)
        if entry:
            entries.append(entry)
    for spec in PUBLISHED_LISTS:
        entry = collect_published(spec, problems)
        if entry:
            entries.append(entry)
    for spec in STATIC_ENTRIES:
        entries.append({**spec, "cidrs": sorted(spec["cidrs"], key=_cidr_sort_key)})

    entries.sort(key=lambda e: e["provider"])
    _validate(entries, previous, problems)
    return {
        "_comment": (
            "GENERATED by scripts/refresh_ip_ranges.py -- do not edit by hand. "
            "Read at runtime for offline CIDR attribution; the server performs "
            "no network I/O for this."
        ),
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": entries,
    }


def _comparable(doc: dict) -> str:
    """Everything except the timestamp, so an unchanged refresh is a no-op."""
    return json.dumps({k: v for k, v in doc.items() if k != "generated_at"},
                      sort_keys=True, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify the committed file is current; do not write")
    args = ap.parse_args()

    previous = None
    if OUTPUT.exists():
        try:
            previous = json.loads(OUTPUT.read_text())
        except json.JSONDecodeError:
            pass

    problems: list[str] = []
    doc = build(problems, previous)

    for p in problems:
        print(f"WARNING: {p}", file=sys.stderr)

    total = sum(len(e["cidrs"]) for e in doc["entries"])
    print(f"{len(doc['entries'])} providers, {total} CIDRs")
    for e in doc["entries"]:
        print(f"  {e['provider']:20} {e['confidence']:10} {len(e['cidrs']):4} cidr  ({e['source']})")

    if previous and _comparable(previous) == _comparable(doc):
        print("unchanged")
        return 1 if problems else 0

    if args.check:
        print("STALE: committed ip_ranges.json differs from upstream", file=sys.stderr)
        return 2

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUTPUT}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
