"""Describing an exception so the message is never empty.

Every tool handler ends in `except Exception as e: ... f"Failed to X: {str(e)}"`.
That reads fine until the exception carries no message, and the Illumio SDK
raises exactly that: `IllumioApiException()` with no args stringifies to the
empty string, so the caller receives

    Failed to create ringfence:

naming neither a cause nor even a kind of failure. Observed for real while
diagnosing two transient PCE errors -- the tests failed with messages that said
nothing, which made a 30-second diagnosis into a long one.
"""
from __future__ import annotations


def describe_error(exc: BaseException) -> str:
    """Human-readable cause that is never empty.

    The exception type is always included: "IllumioApiException: 502 Bad
    Gateway" tells a reader more than "502 Bad Gateway", and when the message is
    missing the type is the only information there is.
    """
    name = type(exc).__name__
    text = str(exc).strip()
    if text:
        return f"{name}: {text}"
    # Fall back to anything the args carry, then to the bare type name.
    for arg in getattr(exc, "args", ()) or ():
        rendered = str(arg).strip()
        if rendered:
            return f"{name}: {rendered}"
    return f"{name} (no detail provided)"
