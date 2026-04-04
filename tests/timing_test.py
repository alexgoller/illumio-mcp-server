#!/usr/bin/env python3
"""Timing measurement for MCP tool calls at multiple layers.

Layer 1: Direct PCE API (illumio SDK)
Layer 2: MCP stdio harness (same as pytest tests)

Run: cd /Volumes/MacMini-4TB/alex-extern/git/illumio-mcp-server && .venv/bin/python3 tests/timing_test.py
"""
import asyncio
import json
import os
import sys
import time

import dotenv
dotenv.load_dotenv()

from illumio import PolicyComputeEngine
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


def get_pce():
    pce = PolicyComputeEngine(
        os.getenv("PCE_HOST"),
        port=os.getenv("PCE_PORT"),
        org_id=os.getenv("PCE_ORG_ID"),
    )
    pce.set_credentials(os.getenv("API_KEY"), os.getenv("API_SECRET"))
    pce._session.verify = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")
    return pce


def get_server_params():
    venv_python = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python3")
    env = {
        **os.environ,
        "PCE_HOST": os.getenv("PCE_HOST", ""),
        "PCE_PORT": os.getenv("PCE_PORT", ""),
        "PCE_ORG_ID": os.getenv("PCE_ORG_ID", ""),
        "API_KEY": os.getenv("API_KEY", ""),
        "API_SECRET": os.getenv("API_SECRET", ""),
    }
    return StdioServerParameters(command=venv_python, args=["-m", "illumio_mcp"], env=env)


# ── Layer 1: Direct PCE API calls ──────────────────────────────────────────

def time_direct_pce():
    print("\n=== Layer 1: Direct PCE API ===")
    pce = get_pce()

    calls = [
        ("check_connection", lambda: pce.check_connection()),
        ("labels.get(max=5)", lambda: pce.labels.get(params={"max_results": 5})),
        ("services.get(max=5)", lambda: pce.services.get(params={"max_results": 5})),
        ("ip_lists.get(max=5)", lambda: pce.ip_lists.get(params={"max_results": 5})),
        ("workloads.get(max=5)", lambda: pce.workloads.get(params={"max_results": 5})),
        # Also test without max_results to see if size is the issue
        ("labels.get(no limit)", lambda: pce.labels.get()),
        ("services.get(no limit)", lambda: pce.services.get()),
        ("ip_lists.get(no limit)", lambda: pce.ip_lists.get()),
        ("workloads.get(no limit)", lambda: pce.workloads.get()),
    ]

    results = {}
    for name, fn in calls:
        t0 = time.monotonic()
        try:
            result = fn()
            elapsed = time.monotonic() - t0
            count = len(result) if isinstance(result, list) else "n/a"
            size = len(json.dumps(str(result))) if isinstance(result, list) else "n/a"
            print(f"  {name:30s} {elapsed:7.2f}s  items={count}  json_chars={size}")
            results[name] = {"time": elapsed, "items": count, "chars": size}
        except Exception as e:
            elapsed = time.monotonic() - t0
            print(f"  {name:30s} {elapsed:7.2f}s  ERROR: {e}")
            results[name] = {"time": elapsed, "error": str(e)}
    return results


# ── Layer 2: MCP stdio harness ─────────────────────────────────────────────

async def time_mcp_harness():
    print("\n=== Layer 2: MCP stdio harness ===")

    tools = [
        ("check-pce-connection", {}),
        ("get-labels", {"max_results": 5}),
        ("get-services", {"max_results": 5}),
        ("get-iplists", {"max_results": 5}),
        ("get-workloads", {"max_results": 5}),
        ("get-labels", {}),
        ("get-services", {}),
        ("get-iplists", {}),
        ("get-workloads", {}),
    ]

    results = {}

    # Measure total time including server startup
    for name, args in tools:
        label = f"{name}({json.dumps(args) if args else 'no args'})"
        t0 = time.monotonic()
        try:
            async with stdio_client(get_server_params()) as (read, write):
                t_connected = time.monotonic()
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    t_init = time.monotonic()
                    result = await session.call_tool(name, args)
                    t_done = time.monotonic()

            text = result.content[0].text if result.content else ""
            size = len(text)
            print(f"  {label:55s}  startup={t_connected-t0:.2f}s  init={t_init-t_connected:.2f}s  call={t_done-t_init:.2f}s  total={t_done-t0:.2f}s  chars={size}")
            results[label] = {
                "startup": t_connected - t0,
                "init": t_init - t_connected,
                "call": t_done - t_init,
                "total": t_done - t0,
                "chars": size,
            }
        except Exception as e:
            elapsed = time.monotonic() - t0
            print(f"  {label:55s}  {elapsed:.2f}s  ERROR: {e}")
            results[label] = {"time": elapsed, "error": str(e)}

    # Also measure reuse: multiple calls on same session
    print("\n  --- Reuse session (all calls on one session) ---")
    t0_total = time.monotonic()
    try:
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                t_init = time.monotonic()
                print(f"  Session startup+init: {t_init - t0_total:.2f}s")

                for name, args in tools:
                    label = f"{name}({json.dumps(args) if args else 'no args'})"
                    t0 = time.monotonic()
                    result = await session.call_tool(name, args)
                    elapsed = time.monotonic() - t0
                    text = result.content[0].text if result.content else ""
                    print(f"    {label:55s}  call={elapsed:.2f}s  chars={len(text)}")
    except Exception as e:
        print(f"  Session reuse ERROR: {e}")

    return results


def main():
    print("=" * 70)
    print("Illumio MCP Timing Investigation")
    print("=" * 70)

    # Layer 1
    direct_results = time_direct_pce()

    # Layer 2
    mcp_results = asyncio.run(time_mcp_harness())

    print("\n" + "=" * 70)
    print("DONE")


if __name__ == "__main__":
    main()
