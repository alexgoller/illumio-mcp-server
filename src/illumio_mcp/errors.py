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


MAX_CAUSE_DEPTH = 3


def _describe_one(exc: BaseException) -> str:
    name = type(exc).__name__
    text = str(exc).strip()
    if text:
        return f"{name}: {text}"
    for arg in getattr(exc, "args", ()) or ():
        rendered = str(arg).strip()
        if rendered:
            return f"{name}: {rendered}"
    return f"{name} (no detail provided)"


def describe_error(exc: BaseException) -> str:
    """Human-readable cause that is never empty, following the cause chain.

    The exception type is always included: "IllumioApiException: 502 Bad
    Gateway" tells a reader more than "502 Bad Gateway", and when the message is
    missing the type is the only information there is.

    The chain matters because the Illumio SDK does `raise
    IllumioApiException(message) from e`, and when it cannot build a message the
    real HTTP error is left in __cause__. Reporting only the outer exception
    produced

        Failed to create ringfence: IllumioApiException (no detail provided)

    which says a call failed but not why. Following __cause__ recovers the
    "502 Server Error: Bad Gateway" that actually explains it.
    """
    parts = [_describe_one(exc)]
    seen = {id(exc)}
    cause = exc.__cause__ or exc.__context__
    depth = 0
    while cause is not None and id(cause) not in seen and depth < MAX_CAUSE_DEPTH:
        seen.add(id(cause))
        rendered = _describe_one(cause)
        # Skip a cause that adds nothing beyond what is already shown.
        if rendered not in parts:
            parts.append(rendered)
        cause = cause.__cause__ or cause.__context__
        depth += 1
    return " <- ".join(parts)
