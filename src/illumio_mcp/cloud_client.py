"""HTTP clients for the Illumio Cloud Platform APIs.

Two clients, one auth model. The April branch gave the traffic client
x-api-key / x-api-secret headers; measured on 2026-11-08 against
cloud.illum.io, that answers 401 and Basic + X-Tenant-Id authenticates (the
FQS endpoint then failed upstream with 500 "Failed to read CSI value" on the
test tenant -- an entitlement or back-end error, surfaced as such, not an
auth one). Both clients therefore send Basic auth plus the tenant header.
  CloudPlatformClient  inventory and label assignment
  CloudTrafficClient   unified traffic (FQS) async queries

Both read CLOUD_API_HOST, CLOUD_API_KEY, CLOUD_API_SECRET, CLOUD_TENANT_ID at
construction time (never at import), carry the same bounded retry policy and
request timeout as the PCE client -- a dead endpoint becomes an error, not a
hang -- and are built once per process by the accessors below.
"""
from __future__ import annotations

import base64
import os
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

from .pce import BoundedRetry, PCE_REQUEST_TIMEOUT, PCE_RETRIES


def _settings() -> dict:
    return {
        "host": (os.getenv("CLOUD_API_HOST") or "").rstrip("/"),
        "key": os.getenv("CLOUD_API_KEY") or "",
        "secret": os.getenv("CLOUD_API_SECRET") or "",
        "tenant": os.getenv("CLOUD_TENANT_ID") or "",
        "verify": os.getenv("CLOUD_TLS_VERIFY", "true").lower() not in ("false", "0", "no"),
    }


def _session(headers: dict, verify: bool) -> requests.Session:
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json", "Accept": "application/json", **headers})
    s.verify = verify
    adapter = HTTPAdapter(max_retries=BoundedRetry(
        total=int(os.getenv("MCP_PCE_RETRIES", PCE_RETRIES)), backoff_factor=1, backoff_max=10.0,
        status_forcelist=[429, 500, 502, 503, 504], respect_retry_after_header=True))
    s.mount("https://", adapter); s.mount("http://", adapter)
    return s


class _Base:
    def __init__(self, headers: dict):
        cfg = _settings()
        if not cfg["host"]:
            raise RuntimeError("CLOUD_API_HOST is not set")
        self._base_url = cfg["host"]
        self._timeout = int(os.getenv("MCP_PCE_REQUEST_TIMEOUT", PCE_REQUEST_TIMEOUT))
        self._session = _session(headers, cfg["verify"])

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _call(self, method: str, path: str, **kw):
        resp = self._session.request(method, self._url(path), timeout=self._timeout, **kw)
        resp.raise_for_status()
        return resp.json()


class CloudPlatformClient(_Base):
    """Inventory and labeling: Basic auth plus X-Tenant-Id."""

    def __init__(self):
        super().__init__(_basic_headers())

    def post_inventory(self, body: dict) -> dict:
        """POST /api/v1/inventory/resources -- list/filter cloud resources."""
        return self._call("POST", "/api/v1/inventory/resources", json=body)

    def post_label_assignments(self, body: dict) -> dict:
        """POST /api/v1/label_assignments -- add/remove labels on cloud resources."""
        return self._call("POST", "/api/v1/label_assignments", json=body)


def _basic_headers() -> dict:
    cfg = _settings()
    creds = base64.b64encode(f"{cfg['key']}:{cfg['secret']}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "X-Tenant-Id": cfg["tenant"]}


class CloudTrafficClient(_Base):
    """Unified traffic (FQS): Basic auth plus X-Tenant-Id, like inventory."""

    def __init__(self):
        super().__init__(_basic_headers())

    def get_queries(self) -> dict:
        return self._call("GET", "/api/v1/fqs/async_queries/flows")

    def create_query(self, body: dict) -> dict:
        return self._call("POST", "/api/v1/fqs/async_queries/flows", json=body)

    def download_flows(self, uuid: str, offset: int = 0, limit: int = 5000) -> dict:
        return self._call("GET", f"/api/v1/fqs/async_queries/flows/download/{uuid}",
                          params={"offset": offset, "limit": limit})


_platform: Optional[CloudPlatformClient] = None
_traffic: Optional[CloudTrafficClient] = None


def get_cloud_platform_client() -> CloudPlatformClient:
    global _platform
    if _platform is None:
        _platform = CloudPlatformClient()
    return _platform


def get_cloud_traffic_client() -> CloudTrafficClient:
    global _traffic
    if _traffic is None:
        _traffic = CloudTrafficClient()
    return _traffic


def reset_clients() -> None:
    """Tests change the environment between cases."""
    global _platform, _traffic
    _platform = _traffic = None
