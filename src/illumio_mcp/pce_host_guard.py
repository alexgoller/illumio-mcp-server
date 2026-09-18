"""Validate a user-supplied PCE hostname before we connect to it.

From the 2026-05-13 review: register-pce-credentials takes pce_host from any
authenticated user, and the server then connects to it. That is authenticated
SSRF -- the server can be pointed at anything reachable from its own network.

The trap in the obvious fix
---------------------------

The review recommends rejecting "loopback/link-local/private-range" addresses.
Rejecting private ranges would break the majority of real Illumio deployments:
an on-prem PCE lives on RFC1918 by design. A guard that blocks 10.0.0.0/8 is a
guard that gets switched off.

So this blocks what is actually dangerous and allows what is actually normal:

  BLOCKED   loopback        127.0.0.0/8, ::1     the server's own services
            link-local      169.254.0.0/16       cloud metadata lives at
                                                 169.254.169.254 -- the real
                                                 prize in an SSRF
            unspecified     0.0.0.0, ::
            multicast / reserved
  ALLOWED   RFC1918 and everything else -- where a real PCE is

  MCP_ALLOWED_PCE_HOSTS turns this into a strict allowlist for operators who
  want one; when set, nothing outside it is accepted.

Resolution caveat, stated plainly: we check the addresses a hostname resolves to
at registration time. A name that resolves differently later (DNS rebinding)
is not caught here. Closing that needs pinning the resolved address and
connecting to it directly, which the Illumio SDK does not expose -- so the
allowlist is the answer for environments that care.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket

logger = logging.getLogger(__name__)

ALLOWLIST_ENV = "MCP_ALLOWED_PCE_HOSTS"


class PCEHostRejected(ValueError):
    """A PCE host that must not be connected to. Message is user-facing."""


def _allowlist() -> set[str]:
    raw = os.environ.get(ALLOWLIST_ENV, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}



def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_blocked(addr: ipaddress._BaseAddress) -> str | None:
    if addr.is_loopback:
        return "a loopback address (the server's own services)"
    if addr.is_link_local:
        return "a link-local address (cloud instance metadata lives here)"
    if addr.is_unspecified:
        return "the unspecified address"
    if addr.is_multicast:
        return "a multicast address"
    if addr.is_reserved:
        return "a reserved address"
    return None


def validate_pce_host(host: str, *, resolve: bool = True) -> str:
    """Return the host if acceptable, else raise PCEHostRejected."""
    if not host or not str(host).strip():
        raise PCEHostRejected("pce_host is required")

    cleaned = str(host).strip()
    # Accept a bare hostname or a URL-ish value; the SDK wants the hostname.
    for prefix in ("https://", "http://"):
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix):]
    cleaned = cleaned.split("/", 1)[0].split("?", 1)[0]
    if "@" in cleaned:
        # user:pass@host smuggles a different target past naive checks
        raise PCEHostRejected(
            f"pce_host {host!r} contains credentials or an '@'; give the hostname only"
        )
    # Port stripping has to know about IPv6. A bare "::1" is all colons, so a
    # naive rsplit(":") turns it into ":" -- which then fails to resolve and is
    # reported as a DNS error instead of the loopback address it plainly is.
    if cleaned.startswith("["):                 # [2001:db8::1]:8443
        host_part, _, rest = cleaned[1:].partition("]")
        cleaned = host_part
    elif _looks_like_ip(cleaned):               # bare IPv6, leave intact
        pass
    elif cleaned.count(":") == 1:               # host:port
        cleaned = cleaned.rsplit(":", 1)[0]

    allowed = _allowlist()
    if allowed:
        if cleaned.lower() not in allowed:
            raise PCEHostRejected(
                f"pce_host {cleaned!r} is not in {ALLOWLIST_ENV}. "
                f"Permitted: {sorted(allowed)}"
            )
        return cleaned

    # Literal address: check it directly.
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        addr = None
    if addr is not None:
        reason = _is_blocked(addr)
        if reason:
            raise PCEHostRejected(f"pce_host {cleaned!r} is {reason}")
        return cleaned

    if not resolve:
        return cleaned

    try:
        infos = socket.getaddrinfo(cleaned, None)
    except socket.gaierror as e:
        # Deliberately NOT fatal. Failing closed here buys no security and
        # breaks real deployments:
        #
        #   a name that does not resolve cannot be an SSRF target right now,
        #   and if it starts resolving to something dangerous later, that is
        #   DNS rebinding -- which this check never closed anyway (see the
        #   module docstring);
        #
        #   meanwhile split-horizon DNS, a PCE not yet published in DNS, and
        #   registration from a host without resolver access are all ordinary
        #   and legitimate.
        #
        # The connection attempt fails later with a clear error, which is the
        # right place for "that hostname is wrong" to surface.
        logger.info("pce_host %r did not resolve at registration (%s); "
                    "allowing, connection will surface any error", cleaned, e)
        return cleaned

    # EVERY address must be acceptable. A name resolving to both a public and a
    # metadata address would otherwise pass on the public one and be connected
    # to on the other.
    for info in infos:
        try:
            resolved = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        reason = _is_blocked(resolved)
        if reason:
            raise PCEHostRejected(
                f"pce_host {cleaned!r} resolves to {resolved}, which is {reason}. "
                f"Set {ALLOWLIST_ENV} if this is deliberate."
            )
    return cleaned
