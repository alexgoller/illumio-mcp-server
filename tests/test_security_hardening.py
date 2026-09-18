"""The four open findings from the 2026-05-13 security review.

Each test names the exposure it closes, so a future change that reopens one
fails with the reason rather than a bare assertion.
"""
import time

import pytest

from illumio_mcp.auth.rate_limit import RateLimiter, TokenBucket
from illumio_mcp.pce_host_guard import validate_pce_host, PCEHostRejected, ALLOWLIST_ENV
from illumio_mcp.transport.request_id import sanitize_request_id, MAX_REQUEST_ID_LEN
from illumio_mcp.transport.security_headers import (
    BASE_HEADERS, NO_STORE, needs_no_store,
)
from illumio_mcp.tools import TOOL_REGISTRY


# ----- finding: missing HTTP security headers -----

@pytest.mark.parametrize("header", [
    "X-Content-Type-Options", "X-Frame-Options",
    "Referrer-Policy", "Content-Security-Policy",
])
def test_security_headers_present(header):
    assert header in BASE_HEADERS


def test_framing_is_denied():
    """Without this the /setup page can be framed cross-origin for clickjacking."""
    assert BASE_HEADERS["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in BASE_HEADERS["Content-Security-Policy"]


def test_csp_denies_by_default():
    """The XSS this backstops is fixed; the CSP is so the next one is not a
    single escaping bug away from executing."""
    csp = BASE_HEADERS["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "base-uri 'none'" in csp


# ----- finding: Cache-Control no-store on /setup and /confirm -----

@pytest.mark.parametrize("path", ["/setup", "/confirm", "/confirm/anything"])
def test_sensitive_paths_are_no_store(path):
    assert needs_no_store(path)


@pytest.mark.parametrize("path", ["/healthz", "/mcp", "/readyz", "/setupsomething"])
def test_ordinary_paths_are_cacheable(path):
    assert not needs_no_store(path)


def test_no_store_is_actually_no_store():
    """/confirm returns a single-use token with a 120s TTL; a shared browser
    profile or proxy that cached it could replay it inside that window."""
    assert "no-store" in NO_STORE["Cache-Control"]


# ----- finding: no rate limiting -----

def test_limit_is_enforced_per_subject():
    rl = RateLimiter({"/confirm": 3})
    assert [rl.check("a", "/confirm")[0] for _ in range(5)] == [True, True, True, False, False]


def test_one_subject_cannot_exhaust_anothers_budget():
    """IP-keyed limiting would throttle a whole office behind one NAT; the
    identity is what is being abused."""
    rl = RateLimiter({"/confirm": 2})
    for _ in range(3):
        rl.check("noisy", "/confirm")
    assert rl.check("quiet", "/confirm")[0] is True


def test_unlimited_paths_pass_through():
    rl = RateLimiter({"/confirm": 1})
    for _ in range(50):
        assert rl.check("a", "/healthz")[0] is True


def test_longest_prefix_wins():
    rl = RateLimiter({"/mcp": 100, "/mcp/special": 1})
    assert rl.limit_for("/mcp/special")[1] == 1
    assert rl.limit_for("/mcp/other")[1] == 100


def test_zero_disables_the_limit():
    rl = RateLimiter({"/confirm": 0})
    assert all(rl.check("a", "/confirm")[0] for _ in range(20))


def test_retry_after_is_a_usable_number():
    rl = RateLimiter({"/confirm": 6})
    for _ in range(6):
        rl.check("a", "/confirm")
    allowed, retry = rl.check("a", "/confirm")
    assert allowed is False
    assert 1 <= retry <= 60


def test_bucket_refills_over_time():
    bucket = TokenBucket(capacity=1, refill_per_sec=1000.0)
    assert bucket.take() is True
    assert bucket.take() is False
    time.sleep(0.01)
    assert bucket.take() is True


def test_buckets_are_pruned_so_the_dict_cannot_grow_forever():
    """The same unbounded-growth shape the review flagged for used_jti."""
    rl = RateLimiter({"/confirm": 5})
    for i in range(50):
        rl.check(f"user-{i}", "/confirm")
    assert len(rl._buckets) == 50
    assert rl.prune(max_idle_seconds=-1) == 50
    assert len(rl._buckets) == 0


# ----- finding: SSRF via user-controlled pce_host -----

@pytest.mark.parametrize("host,reason", [
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("169.254.169.254", "link-local"),   # cloud metadata, the real prize
    ("fe80::1", "link-local"),
    ("0.0.0.0", "unspecified"),
])
def test_dangerous_targets_are_blocked(host, reason):
    with pytest.raises(PCEHostRejected) as e:
        validate_pce_host(host)
    assert reason in str(e.value)


@pytest.mark.parametrize("host", ["10.1.2.3", "192.168.1.50", "172.16.5.5"])
def test_rfc1918_is_allowed_because_that_is_where_real_pces_live(host):
    """The review said to block private ranges. Doing so would break the
    majority of real Illumio deployments -- an on-prem PCE is on RFC1918 by
    design -- and a guard that breaks the normal case gets switched off."""
    assert validate_pce_host(host) == host


def test_ipv6_is_parsed_not_mangled():
    """A naive rsplit(':') turns '::1' into ':', which then fails to resolve and
    is reported as a DNS error instead of the loopback it plainly is."""
    assert validate_pce_host("2001:db8::1") == "2001:db8::1"
    assert validate_pce_host("[2001:db8::1]:8443") == "2001:db8::1"


def test_port_and_scheme_are_stripped():
    assert validate_pce_host("https://10.1.2.3:8443/api/v2") == "10.1.2.3"
    assert validate_pce_host("10.1.2.3:8443") == "10.1.2.3"


def test_credentials_in_host_are_rejected():
    """user:pass@host smuggles a different target past a naive check."""
    with pytest.raises(PCEHostRejected, match="@"):
        validate_pce_host("user:pw@169.254.169.254")


def test_empty_host_rejected():
    with pytest.raises(PCEHostRejected):
        validate_pce_host("")


def test_allowlist_makes_everything_else_fail(monkeypatch):
    monkeypatch.setenv(ALLOWLIST_ENV, "pce.corp.example.com, 10.1.2.3")
    assert validate_pce_host("10.1.2.3") == "10.1.2.3"
    assert validate_pce_host("pce.corp.example.com") == "pce.corp.example.com"
    with pytest.raises(PCEHostRejected, match=ALLOWLIST_ENV):
        validate_pce_host("other.example.com")


def test_allowlist_also_blocks_metadata(monkeypatch):
    monkeypatch.setenv(ALLOWLIST_ENV, "pce.corp.example.com")
    with pytest.raises(PCEHostRejected):
        validate_pce_host("169.254.169.254")


def test_register_credentials_is_not_open_to_readers():
    """The tool makes the server connect to a caller-chosen host."""
    roles = TOOL_REGISTRY["register-pce-credentials"].roles
    assert "reader" not in roles
    assert {"operator", "admin"} <= set(roles)


# ----- finding: unsanitised X-Request-Id -----

@pytest.mark.parametrize("value", [
    "bad\r\nInjected: header",
    "nul\x00byte",
    "a" * (MAX_REQUEST_ID_LEN + 1),
    "spaces are out",
    "",
    None,
])
def test_unsafe_request_ids_are_discarded(value):
    """Discarding beats scrubbing: a partially-rewritten id no longer
    correlates with anything client-side, so it is worse than a fresh uuid."""
    assert sanitize_request_id(value) is None


@pytest.mark.parametrize("value", ["abc-123", "req_1.2:3", "A" * MAX_REQUEST_ID_LEN])
def test_safe_request_ids_survive(value):
    assert sanitize_request_id(value) == value


# ----- the middleware actually applies, not just the helpers -----

@pytest.fixture(scope="module")
def client():
    """Dev-insecure app: no auth, which is enough to prove the header and
    request-id middleware run. Unit tests above cover the limiter's logic; it
    only engages once a JWT subject exists."""
    from starlette.testclient import TestClient
    from illumio_mcp.transport.http import _build_app
    app = _build_app(None, None, None, None, None, None)
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("header,expected", list(BASE_HEADERS.items()))
def test_headers_reach_a_real_response(client, header, expected):
    assert client.get("/healthz").headers.get(header) == expected


def test_healthz_is_not_marked_no_store(client):
    """no-store belongs on the sensitive paths, not on everything -- a
    blanket no-store would make the liveness probe uncacheable for no reason."""
    assert client.get("/healthz").headers.get("Cache-Control") is None


def test_a_hostile_request_id_never_reaches_the_response(client):
    hostile = "evil value\twith control chars"
    echoed = client.get("/healthz", headers={"X-Request-Id": hostile}).headers["X-Request-Id"]
    assert echoed != hostile
    assert all(c not in echoed for c in "\t\r\n ")


def test_a_clean_request_id_is_preserved_for_correlation(client):
    """Sanitising must not break the legitimate use: correlating a client's
    request with the server's audit record."""
    assert client.get("/healthz", headers={"X-Request-Id": "trace-abc-123"}
                      ).headers["X-Request-Id"] == "trace-abc-123"


def test_unresolvable_hosts_are_allowed_not_rejected():
    """Failing closed on DNS failure buys no security and breaks real use.

    An unresolvable name is not an SSRF target now; if it resolves to something
    dangerous later that is DNS rebinding, which this check never closed. Split
    horizon DNS, a PCE not yet in DNS, and registration from a host without
    resolver access are all ordinary. The first cut rejected these and broke
    per-user credential registration entirely.
    """
    assert validate_pce_host("pce.example") == "pce.example"
    assert validate_pce_host("pce.internal.corp") == "pce.internal.corp"


def test_resolvable_dangerous_names_are_still_blocked():
    """The protection that matters is unaffected by the above."""
    with pytest.raises(PCEHostRejected, match="loopback"):
        validate_pce_host("localhost")


def test_stored_host_matches_what_the_sdk_will_dial():
    """The guard normalises scheme and port away. That is not cosmetic: the
    Illumio SDK normalises identically, so validating one string and storing
    another would be a parser differential -- the classic shape of a bypass.
    Verified against the SDK rather than assumed."""
    from illumio import PolicyComputeEngine
    for raw in ("https://pce.example", "pce.example", "https://10.1.2.3:8443"):
        guarded = validate_pce_host(raw, resolve=False)
        sdk_host = PolicyComputeEngine(raw, port=8443, org_id=1)._hostname
        assert guarded == sdk_host, f"{raw}: guard={guarded} sdk={sdk_host}"
