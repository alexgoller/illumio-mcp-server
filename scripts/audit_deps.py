#!/usr/bin/env python3
"""Check installed dependencies against the OSV vulnerability database.

Queries OSV directly rather than depending on a scanner, so it needs nothing
beyond the standard library and works the same locally and in CI.

    .venv/bin/python scripts/audit_deps.py            # report, exit 1 on findings
    .venv/bin/python scripts/audit_deps.py --warn     # report, always exit 0
"""
from __future__ import annotations

import json
import sys
import urllib.request

OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def installed() -> dict[str, str]:
    """Every distribution in the current environment.

    Uses importlib.metadata rather than `pip freeze`: a uv-created venv has no
    pip, and this reads the same metadata without spawning a subprocess.
    """
    import importlib.metadata as md

    pkgs: dict[str, str] = {}
    for dist in md.distributions():
        name = (dist.metadata["Name"] or "").strip()
        version = (dist.version or "").strip()
        if name and version:
            pkgs[name.lower().replace("_", "-")] = version
    return pkgs


def query(pkgs: dict[str, str]) -> dict[str, list[str]]:
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
               for n, v in sorted(pkgs.items())]
    req = urllib.request.Request(
        OSV_BATCH,
        data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"},
    )
    results = json.load(urllib.request.urlopen(req, timeout=120))["results"]
    hits: dict[str, list[str]] = {}
    for q, r in zip(queries, results):
        vulns = r.get("vulns") or []
        if vulns:
            hits[f"{q['package']['name']}=={q['version']}"] = [v["id"] for v in vulns]
    return hits


def main() -> int:
    pkgs = installed()
    if not pkgs:
        print("could not determine installed packages", file=sys.stderr)
        return 1
    hits = query(pkgs)
    total = sum(len(v) for v in hits.values())
    print(f"OSV: {len(pkgs)} packages scanned, {total} advisories "
          f"across {len(hits)} packages")
    for pkg, ids in sorted(hits.items()):
        print(f"  {pkg}: {', '.join(ids)}")
    if total and "--warn" not in sys.argv:
        print("\nRaise the floor in pyproject.toml "
              "([tool.uv] constraint-dependencies for transitive packages).")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
