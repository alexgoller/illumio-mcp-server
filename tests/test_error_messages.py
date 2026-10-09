"""An error message must never name nothing.

Every handler ends in `f"Failed to X: {describe_error(e)}"`. That used to be
`str(e)`, which is empty for an exception carrying no message -- and the Illumio
SDK raises exactly that. The result was

    Failed to create ringfence:

Observed for real while diagnosing two transient PCE failures: the tests failed
with messages that said nothing.
"""
import pathlib

import pytest
from illumio.exceptions import IllumioApiException

from illumio_mcp.errors import describe_error


def test_message_is_never_empty_even_with_no_detail():
    assert describe_error(IllumioApiException()).strip()
    assert "IllumioApiException" in describe_error(IllumioApiException())


def test_the_sdk_really_does_produce_an_empty_string():
    """The premise, asserted rather than assumed."""
    assert str(IllumioApiException()) == ""


def test_type_is_always_included():
    """'IllumioApiException: 502 Bad Gateway' tells a reader more than
    '502 Bad Gateway', and when there is no message the type is all there is."""
    assert describe_error(IllumioApiException("502 Bad Gateway")) == \
        "IllumioApiException: 502 Bad Gateway"


@pytest.mark.parametrize("exc", [
    ValueError("bad input"), KeyError("missing"), RuntimeError(),
    IllumioApiException(""), Exception(), TimeoutError(),
])
def test_every_exception_shape_yields_something(exc):
    out = describe_error(exc)
    assert out.strip()
    assert type(exc).__name__ in out


def test_falls_back_to_args_when_str_is_empty():
    class Quiet(Exception):
        def __str__(self): return ""
    assert "detail-in-args" in describe_error(Quiet("detail-in-args"))


def test_no_handler_still_interpolates_bare_str_e():
    """A source guard: the next handler written must not reintroduce the
    pattern, which is invisible until an exception happens to be empty."""
    offenders = []
    for path in sorted(pathlib.Path("src/illumio_mcp/tools").glob("*.py")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "{str(e)}" in line:
                offenders.append(f"{path.name}:{n}")
    assert not offenders, (
        "use describe_error(e) -- str(e) is empty for exceptions with no "
        f"message: {offenders}"
    )


# ----- the cause chain is where the real reason lives -----

def test_cause_chain_is_followed():
    """The Illumio SDK does `raise IllumioApiException(message) from e`, and when
    it cannot build a message the real HTTP error is left in __cause__. Showing
    only the outer exception produced

        Failed to create ringfence: IllumioApiException (no detail provided)

    which says a call failed but not why. Observed for real on a 502."""
    from requests.exceptions import HTTPError
    try:
        try:
            raise HTTPError("502 Server Error: Bad Gateway")
        except HTTPError as inner:
            raise IllumioApiException() from inner
    except IllumioApiException as outer:
        out = describe_error(outer)
    assert "IllumioApiException" in out
    assert "502" in out, "the cause that actually explains the failure is missing"


def test_implicit_context_is_followed_too():
    """A bare `raise X` inside an except block sets __context__, not __cause__."""
    try:
        try:
            raise KeyError("missing-key")
        except KeyError:
            raise IllumioApiException()
    except IllumioApiException as e:
        assert "missing-key" in describe_error(e)


def test_chain_depth_is_bounded():
    exc = ValueError("root")
    for i in range(12):
        try:
            raise RuntimeError(f"layer-{i}") from exc
        except RuntimeError as e:
            exc = e
    out = describe_error(exc)
    assert out.count(" <- ") <= 3, "an unbounded chain would flood the message"


def test_duplicate_causes_are_not_repeated():
    try:
        try:
            raise ValueError("same text")
        except ValueError as inner:
            raise ValueError("same text") from inner
    except ValueError as e:
        assert describe_error(e).count("same text") == 1


def test_self_referential_chain_does_not_hang():
    e = RuntimeError("loop")
    e.__cause__ = e
    assert describe_error(e)
