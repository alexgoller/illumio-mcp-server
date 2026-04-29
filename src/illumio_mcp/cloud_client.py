"""HTTP clients for Illumio Cloud Platform APIs.

Two separate clients for two auth models:
- CloudPlatformClient: Basic auth + X-Tenant-Id (inventory + labeling)
- CloudTrafficClient: x-api-key + x-api-secret headers (unified traffic)

Both use the singleton pattern (like pce.py) and requests.Session for connection reuse.
"""

import base64
import logging
import os
import urllib3
import requests

logger = logging.getLogger('illumio_mcp')

# Cloud Platform API (Inventory + Labeling)
CLOUD_API_HOST = os.getenv("CLOUD_API_HOST")
CLOUD_API_KEY = os.getenv("CLOUD_API_KEY")
CLOUD_API_SECRET = os.getenv("CLOUD_API_SECRET")
CLOUD_TENANT_ID = os.getenv("CLOUD_TENANT_ID")

# Unified Traffic API
CLOUD_TRAFFIC_API_KEY = os.getenv("CLOUD_TRAFFIC_API_KEY")
CLOUD_TRAFFIC_API_SECRET = os.getenv("CLOUD_TRAFFIC_API_SECRET")

# Shared
CLOUD_TLS_VERIFY = os.getenv("CLOUD_TLS_VERIFY", "true").lower() not in ("false", "0", "no")

if not CLOUD_TLS_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CloudPlatformClient:
    """Client for Cloud Inventory and Labeling APIs (Basic auth + X-Tenant-Id)."""

    _instance = None

    def __init__(self):
        self._session = requests.Session()
        creds = base64.b64encode(f"{CLOUD_API_KEY}:{CLOUD_API_SECRET}".encode()).decode()
        self._session.headers.update({
            "Authorization": f"Basic {creds}",
            "X-Tenant-Id": CLOUD_TENANT_ID,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._session.verify = CLOUD_TLS_VERIFY
        self._base_url = CLOUD_API_HOST.rstrip("/") if CLOUD_API_HOST else ""

    @classmethod
    def is_configured(cls):
        return all([CLOUD_API_HOST, CLOUD_API_KEY, CLOUD_API_SECRET, CLOUD_TENANT_ID])

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            if not cls.is_configured():
                raise RuntimeError(
                    "Cloud Platform API not configured. "
                    "Set CLOUD_API_HOST, CLOUD_API_KEY, CLOUD_API_SECRET, CLOUD_TENANT_ID environment variables."
                )
            cls._instance = cls()
        return cls._instance

    def _url(self, path):
        return f"{self._base_url}{path}"

    def post_inventory(self, body: dict) -> dict:
        """POST /api/v1/inventory/resources — list/filter cloud resources."""
        resp = self._session.post(self._url("/api/v1/inventory/resources"), json=body)
        resp.raise_for_status()
        return resp.json()

    def post_label_assignments(self, body: dict) -> dict:
        """POST /api/v1/label_assignments — add/remove labels on cloud resources."""
        resp = self._session.post(self._url("/api/v1/label_assignments"), json=body)
        resp.raise_for_status()
        return resp.json()


class CloudTrafficClient:
    """Client for Unified Traffic APIs (x-api-key + x-api-secret headers)."""

    _instance = None

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "x-api-key": CLOUD_TRAFFIC_API_KEY,
            "x-api-secret": CLOUD_TRAFFIC_API_SECRET,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._session.verify = CLOUD_TLS_VERIFY
        self._base_url = (os.getenv("CLOUD_TRAFFIC_API_HOST") or CLOUD_API_HOST or "").rstrip("/")

    @classmethod
    def is_configured(cls):
        return all([CLOUD_TRAFFIC_API_KEY, CLOUD_TRAFFIC_API_SECRET, CLOUD_API_HOST or os.getenv("CLOUD_TRAFFIC_API_HOST")])

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            if not cls.is_configured():
                raise RuntimeError(
                    "Cloud Traffic API not configured. "
                    "Set CLOUD_TRAFFIC_API_KEY, CLOUD_TRAFFIC_API_SECRET, and CLOUD_API_HOST environment variables."
                )
            cls._instance = cls()
        return cls._instance

    def _url(self, path):
        return f"{self._base_url}{path}"

    def get_queries(self) -> dict:
        """GET /api/v1/fqs/async_queries/flows — list async query statuses."""
        resp = self._session.get(self._url("/api/v1/fqs/async_queries/flows"))
        resp.raise_for_status()
        return resp.json()

    def create_query(self, body: dict) -> dict:
        """POST /api/v1/fqs/async_queries/flows — create async traffic flow query."""
        resp = self._session.post(self._url("/api/v1/fqs/async_queries/flows"), json=body)
        resp.raise_for_status()
        return resp.json()

    def download_flows(self, uuid: str, offset: int = 0, limit: int = 5000) -> dict:
        """GET /api/v1/fqs/async_queries/flows/download/{uuid} — download query results."""
        params = {"offset": offset, "limit": limit}
        resp = self._session.get(self._url(f"/api/v1/fqs/async_queries/flows/download/{uuid}"), params=params)
        resp.raise_for_status()
        return resp.json()

    def update_rule_coverage(self, uuid: str, body: dict) -> dict:
        """PUT /api/v1/fqs/async_queries/flows/update_rule_coverage/{uuid}."""
        resp = self._session.put(self._url(f"/api/v1/fqs/async_queries/flows/update_rule_coverage/{uuid}"), json=body)
        resp.raise_for_status()
        return resp.json()
