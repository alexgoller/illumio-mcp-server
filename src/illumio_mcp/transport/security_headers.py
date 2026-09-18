"""Response headers that limit what a response may leak onward.

Two findings from the 2026-05-13 review, together because they are the same
concern -- what a browser or proxy is allowed to do with a response after it
leaves us:

  Missing HTTP security headers
      Without X-Frame-Options the /setup page can be framed cross-origin
      (clickjacking), and without a CSP the stored-XSS finding had no secondary
      mitigation. That XSS is fixed, but defence in depth is the point: the next
      one should not be a single escaping bug away from executing.

  Cache-Control: no-store absent on /setup and /confirm
      /confirm returns a single-use token with a 120s TTL. A shared browser
      profile or transparent proxy that cached it could replay it inside that
      window. /setup renders the authenticated user's sub and iss.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Applied to every response. Conservative by design: this server renders exactly
# one HTML page (/setup), which uses no scripts, no styles from anywhere, and no
# framing -- so the strictest policy that works is the correct one.
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}

# Paths whose responses must never be stored. Prefix match, so /confirm and any
# future sub-path are both covered.
NO_STORE_PREFIXES = ("/setup", "/confirm")

NO_STORE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Expires": "0",
}


def needs_no_store(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in NO_STORE_PREFIXES)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set security headers on every response, and no-store on the sensitive ones.

    Existing headers are not overwritten: a handler that deliberately set its
    own Cache-Control knows something this middleware does not.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        for name, value in BASE_HEADERS.items():
            response.headers.setdefault(name, value)

        if needs_no_store(request.url.path):
            for name, value in NO_STORE.items():
                response.headers.setdefault(name, value)

        return response
