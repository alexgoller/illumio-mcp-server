"""get-pce-capacity: how full is this PCE, and can we read its object limits.

Measured on demo100 (26.30.4), 2026-10-15. Four sources, each optional:

  GET  /traffic_flows/database_metrics      flow storage and retention vs limits,
                                            per flow source (documented, works)
  POST /reports/time_series_statistics      num_managed_workloads over time
                                            (documented; the spec's other two
                                            properties answer 406 on this PCE)
  GET  /events?event_type=*_limit_exceeded  the PCE's own soft/hard limit alarms
  GET  /api/v2/object_limit_profiles        the object-limit API. Root-level, no
       /api/v2/api_usage_limit_profiles     org in the path, absent from the
                                            26.3/26.4 OpenAPI specs, and answers
                                            403 to an org-scoped key -- with a
                                            request.authorization_failed audit
                                            event naming the endpoint. It exists;
                                            it is gated. Report that, do not
                                            flatten it into "no data".

The gated routes' response shape is unknown until a key with access returns a
200; the body is passed through raw and summarised best-effort.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

import mcp.types as types

from ..errors import describe_error
from ..log_scrub import ScrubbedArgs

logger = logging.getLogger('illumio_mcp')

OBJECT_LIMITS_ENDPOINT = "/object_limit_profiles"
API_USAGE_LIMITS_ENDPOINT = "/api_usage_limit_profiles"
WARN_AT_PERCENT = 80.0


def _get(pce, endpoint: str, *, include_org: bool, params=None):
    """Raw GET: status and body without the SDK raising on non-2xx, so a 403
    and a 404 stay distinguishable -- that distinction is the finding."""
    url = pce._build_url(endpoint, include_org)
    return pce._session.request("GET", url, params=params, timeout=pce._timeout)


def _post(pce, endpoint: str, body, *, include_org: bool):
    url = pce._build_url(endpoint, include_org)
    return pce._session.request("POST", url, json=body, timeout=pce._timeout)


def _json(resp):
    try:
        return resp.json()
    except Exception:
        return None


def _pct(value, limit):
    if value is None or not limit:
        return None
    return round(100.0 * float(value) / float(limit), 1)


# ----------------------------------------------------------------- sections

def database_section(pce, warnings: list) -> dict:
    resp = _get(pce, "/traffic_flows/database_metrics", include_org=True)
    if resp.status_code != 200:
        return {"available": False, "http_status": resp.status_code, "reason": resp.text[:200]}
    m = _json(resp) or {}
    out = {
        "available": True,
        "flows_size_gb": m.get("flows_size_gb"),
        "flows_size_gb_limit": m.get("flows_size_gb_limit"),
        "size_percent_of_limit": _pct(m.get("flows_size_gb"), m.get("flows_size_gb_limit")),
        "flows_days": m.get("flows_days"),
        "flows_days_limit": m.get("flows_days_limit"),
        "days_percent_of_limit": _pct(m.get("flows_days"), m.get("flows_days_limit")),
        "flows_per_second": m.get("flows_per_second"),
        "oldest_day": m.get("flows_oldest_day"),
        "newest_day": m.get("flows_newest_day"),
        "backlog": m.get("backlog"),
        "updated_at": m.get("updated_at"),
        "sources": {},
    }
    for name, src in m.items():
        if not isinstance(src, dict) or name == "backlog":
            continue
        row = {
            "flows_size_gb": src.get("flows_size_gb"),
            "flows_size_gb_limit": src.get("flows_size_gb_limit"),
            "size_percent_of_limit": _pct(src.get("flows_size_gb"), src.get("flows_size_gb_limit")),
            "num_flows_days": src.get("num_flows_days"),
            "num_flow_days_limit": src.get("num_flow_days_limit"),
            "days_percent_of_limit": _pct(src.get("num_flows_days"), src.get("num_flow_days_limit")),
        }
        out["sources"][name] = row
        for key, label in (("size_percent_of_limit", "flow storage"), ("days_percent_of_limit", "flow retention")):
            if row[key] is not None and row[key] >= WARN_AT_PERCENT:
                warnings.append(f"{name}: {label} at {row[key]}% of its limit "
                                f"({row['flows_size_gb'] if 'storage' in label else row['num_flows_days']} "
                                f"of {row['flows_size_gb_limit'] if 'storage' in label else row['num_flow_days_limit']})")
    for key, label in (("size_percent_of_limit", "flow storage"), ("days_percent_of_limit", "flow retention")):
        if out[key] is not None and out[key] >= WARN_AT_PERCENT:
            warnings.append(f"total {label} at {out[key]}% of the org limit")
    return out


def workloads_section(pce, lookback_days: int) -> dict:
    body = [{"property": "num_managed_workloads", "resolution": "day", "max_results": lookback_days}]
    resp = _post(pce, "/reports/time_series_statistics", body, include_org=True)
    data = _json(resp)
    if resp.status_code not in (200, 201):
        reason = ""
        if isinstance(data, list) and data and isinstance(data[0], dict):
            reason = f"{data[0].get('token', '')}: {data[0].get('message', '')}"
        return {"available": False, "http_status": resp.status_code, "reason": reason or resp.text[:200]}
    series = []
    for item in data or []:
        if item.get("property") == "num_managed_workloads":
            series = item.get("time_series") or []
    points = [(p.get("start_date"), (p.get("data") or {}).get("count")) for p in series if p.get("data")]
    points = [(d, c) for d, c in points if c is not None]
    if not points:
        return {"available": True, "points": 0}
    points.sort()
    (d0, c0), (d1, c1) = points[0], points[-1]
    return {"available": True, "points": len(points), "earliest_date": d0, "earliest": c0,
            "latest_date": d1, "latest": c1, "change": c1 - c0,
            "series": [{"date": d, "count": c} for d, c in points]}


def events_section(pce, lookback_days: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {}
    for et in ("soft_limit_exceeded", "hard_limit_exceeded"):
        resp = _get(pce, "/events", include_org=True,
                    params={"event_type": et, "timestamp[gte]": since, "max_results": 100})
        events = _json(resp) if resp.status_code == 200 else None
        if not isinstance(events, list):
            out[et] = {"available": False, "http_status": resp.status_code}
            continue
        latest = max(events, key=lambda e: e.get("timestamp", ""), default=None)
        out[et] = {"count": len(events),
                   "latest": ({"timestamp": latest.get("timestamp"), "href": latest.get("href"),
                               "info": [n.get("info") for n in latest.get("notifications", [])][:3]}
                              if latest else None)}
    return out


def _summarise_limits(raw) -> list:
    """Best-effort rows from whatever the gated route returns: anything with a
    name-like key and soft/hard/current numbers."""
    rows = []

    def walk(obj):
        if isinstance(obj, dict):
            keys = {k.lower() for k in obj}
            if {"soft_limit", "hard_limit"} & keys and any(k in keys for k in ("object_type", "name", "key", "object")):
                name = obj.get("object_type") or obj.get("key") or obj.get("object") or obj.get("name")
                cur = obj.get("current") if "current" in obj else obj.get("usage", obj.get("count"))
                soft, hard = obj.get("soft_limit"), obj.get("hard_limit")
                rows.append({"object": name, "current": cur, "soft_limit": soft, "hard_limit": hard,
                             "percent_of_hard": _pct(cur, hard) if hard not in (None, -1) else None,
                             "above_soft": (cur is not None and soft not in (None, -1) and cur > soft)})
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(raw)
    return rows


def limits_section(pce, endpoint: str, warnings: list, label: str) -> dict:
    resp = _get(pce, endpoint, include_org=False)
    api_path = f"/api/v2{endpoint}"
    if resp.status_code == 200:
        raw = _json(resp)
        rows = _summarise_limits(raw)
        for r in rows:
            if r["above_soft"]:
                warnings.append(f"{r['object']}: {r['current']} is above its soft limit {r['soft_limit']}")
            elif r["percent_of_hard"] is not None and r["percent_of_hard"] >= WARN_AT_PERCENT:
                warnings.append(f"{r['object']}: {r['current']} is {r['percent_of_hard']}% of its hard limit {r['hard_limit']}")
        return {"status": "ok", "endpoint": api_path, "summary": rows, "raw": raw}
    if resp.status_code == 403:
        return {"status": "forbidden", "endpoint": api_path, "http_status": 403,
                "request_id": resp.headers.get("X-Request-ID"),
                "message": (f"{api_path} exists on this PCE but this API key is not allowed to read it; the PCE "
                            f"logs a request.authorization_failed audit event for each attempt. It is a "
                            f"root-level resource (no org in the path), absent from the published 26.3/26.4 "
                            f"OpenAPI specs; a Global Organization Owner key, or Illumio support, can say "
                            f"which role unlocks it.")}
    if resp.status_code == 404:
        return {"status": "not_present", "endpoint": api_path, "http_status": 404,
                "message": f"{api_path} is not served by this PCE version."}
    return {"status": "error", "endpoint": api_path, "http_status": resp.status_code,
            "message": resp.text[:300]}


# ------------------------------------------------------------------ handler

def handle_get_pce_capacity(ctx, arguments: dict) -> list:
    logger.debug("GET PCE CAPACITY: %s", ScrubbedArgs(arguments))
    arguments = arguments or {}
    try:
        pce = ctx.pce
        lookback = max(1, min(int(arguments.get('lookback_days', 30)), 365))
        warnings: list = []

        version = _json(_get(pce, "/product_version", include_org=False)) or {}
        payload = {
            "pce": {"host": f"{pce._hostname}:{pce._port}", "org_id": pce.org_id,
                    "version": version.get("version"), "build": version.get("long_display")},
            "window_days": lookback,
            "traffic_database": database_section(pce, warnings),
            "managed_workloads": workloads_section(pce, lookback),
            "limit_events": events_section(pce, lookback),
        }
        if arguments.get('include_object_limits', True):
            payload["object_limits"] = limits_section(pce, OBJECT_LIMITS_ENDPOINT, warnings, "object limits")
            payload["api_usage_limits"] = limits_section(pce, API_USAGE_LIMITS_ENDPOINT, warnings, "API usage limits")

        db = payload["traffic_database"]
        mw = payload["managed_workloads"]
        parts = []
        if db.get("available"):
            parts.append(f"flow storage {db['flows_size_gb']:.2f} of {db['flows_size_gb_limit']} GB "
                         f"({db['size_percent_of_limit']}%), retention {db['flows_days']} of {db['flows_days_limit']} days")
        if mw.get("available") and mw.get("latest") is not None:
            parts.append(f"{mw['latest']} managed workloads ({mw['change']:+d} over {lookback} days)")
        ol = payload.get("object_limits", {})
        if ol.get("status") == "forbidden":
            parts.append("object-limit API present but not readable with this key")
        elif ol.get("status") == "ok":
            parts.append(f"{len(ol['summary'])} object limits read")
        payload["headline"] = "; ".join(parts) or "no capacity data available"
        payload["warnings"] = warnings
        payload["note"] = ("Soft limits log soft_limit_exceeded events; hard limits refuse creates with HTTP 406 "
                           "and log hard_limit_exceeded. On-prem the same table is `illumio-pce-ctl obj-limits list`.")
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]
    except Exception as e:
        error_msg = f"Failed to read PCE capacity: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
