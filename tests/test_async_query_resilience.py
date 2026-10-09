"""The async-query poll: faithful to the SDK, with one deliberate difference.

The SDK's PolicyComputeEngine._async_poll raises `KeyError: 'result'` when the
PCE reports `status: completed` a moment before `result` is populated. That race
is real and is the only reason this replacement exists.

Everything else must match the SDK, because an earlier version of this function
did NOT and broke integration tests that pass on the SDK's version:

  it polled IMMEDIATELY instead of sleeping first, observing transient states
  after submission -- including `status: failed` -- that the SDK's one-second
  wait never sees;

  it imposed a 30s deadline on the whole query, where the SDK has none on
  purpose, because a wide traffic query legitimately runs for minutes.

Both are regression-tested below. A submission retry also briefly existed here
and was removed: a 502 on a POST can mean the request succeeded with only the
response lost, and it was written in response to failures that turned out to be
caused by the two bugs above.
"""
import time
from unittest import mock

import pytest

from illumio_mcp.tools.traffic import poll_async_query, ASYNC_RESULT_GRACE_SECONDS


def _pce(*bodies):
    pce = mock.Mock()
    responses = []
    for b in bodies:
        r = mock.Mock()
        r.raise_for_status.return_value = None
        r.json.return_value = b
        responses.append(r)
    pce.get.side_effect = responses
    return pce


# ----- the race this function exists for -----

def test_completed_without_result_is_polled_through():
    """The SDK raises KeyError: 'result' here. The PCE simply has not written
    the href yet."""
    pce = _pce({"status": "completed"},
               {"status": "completed", "result": "/orgs/1/collection/1"})
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        assert poll_async_query(pce, "/orgs/1/jobs/1") == "/orgs/1/collection/1"


def test_running_then_completed():
    pce = _pce({"status": "running"},
               {"status": "completed", "result": "/orgs/1/collection/2"})
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        assert poll_async_query(pce, "/orgs/1/jobs/1") == "/orgs/1/collection/2"


def test_done_with_href_object():
    """Policy-object collection jobs use {'href': ...}, not a bare string."""
    pce = _pce({"status": "done", "result": {"href": "/orgs/1/collection/3"}})
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        assert poll_async_query(pce, "/orgs/1/jobs/1") == "/orgs/1/collection/3"


def test_completed_without_result_is_bounded():
    """It must not poll forever waiting for an href that never arrives."""
    pce = mock.Mock()
    r = mock.Mock()
    r.raise_for_status.return_value = None
    r.json.return_value = {"status": "completed"}
    pce.get.return_value = r
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        with pytest.raises(RuntimeError, match="no result href"):
            poll_async_query(pce, "/orgs/1/jobs/1", grace=0)


# ----- failures are reported, not retried -----

def test_failed_status_reports_the_pce_message():
    pce = _pce({"status": "failed", "result": {"message": "query too broad"}})
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        with pytest.raises(RuntimeError, match="query too broad"):
            poll_async_query(pce, "/orgs/1/jobs/1")


def test_failed_without_a_message_still_explains_itself():
    pce = _pce({"status": "failed"})
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        with pytest.raises(RuntimeError, match="no message given"):
            poll_async_query(pce, "/orgs/1/jobs/1")


def test_a_failed_query_is_not_retried():
    """The PCE gives no reason, so a retry cannot distinguish transient capacity
    from a genuinely bad query -- and masking the latter hides real problems."""
    pce = _pce({"status": "failed"}, {"status": "completed", "result": "/x"})
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"):
        with pytest.raises(RuntimeError):
            poll_async_query(pce, "/orgs/1/jobs/1")
    assert pce.get.call_count == 1, "status: failed must be terminal"


# ----- regression: the two ways my first version diverged from the SDK -----

def test_it_sleeps_before_the_first_poll():
    """Polling immediately observes transient post-submission states the SDK
    never sees. This cost three full-suite runs misattributed to PCE flakiness."""
    order = []
    pce = mock.Mock()
    r = mock.Mock()
    r.raise_for_status.return_value = None
    r.json.return_value = {"status": "completed", "result": "/x"}
    pce.get.side_effect = lambda *a, **k: (order.append("get"), r)[1]
    with mock.patch("illumio_mcp.tools.traffic.time.sleep",
                    side_effect=lambda s: order.append("sleep")):
        poll_async_query(pce, "/orgs/1/jobs/1")
    assert order[0] == "sleep", f"polled before sleeping: {order}"


def test_there_is_no_overall_deadline():
    """The SDK has none on purpose: a wide traffic query legitimately takes
    minutes, and a deadline turns a slow answer into no answer. An earlier
    version capped the WHOLE query at 30s."""
    slow = [{"status": "running"}] * 40 + [{"status": "completed", "result": "/x"}]
    pce = _pce(*slow)
    # Simulate 10 minutes of elapsed time across the polls.
    with mock.patch("illumio_mcp.tools.traffic.time.sleep"), \
         mock.patch("illumio_mcp.tools.traffic.time.monotonic",
                    side_effect=[i * 20.0 for i in range(200)]):
        assert poll_async_query(pce, "/orgs/1/jobs/1") == "/x"


def test_grace_default_is_a_sane_bound():
    assert 5 <= ASYNC_RESULT_GRACE_SECONDS <= 120


# ----- the shim: poll only, never POST -----

def test_shim_patches_the_poll_and_leaves_post_alone():
    """A submission retry was removed deliberately: a 502 on a POST can mean the
    request succeeded with only the response lost, so retrying risks a duplicate
    -- and for mutations that means writing policy twice."""
    from illumio import PolicyComputeEngine
    from illumio_mcp.pce import _install_async_query_resilience
    pce = PolicyComputeEngine("pce.example", port=443, org_id=1)
    _install_async_query_resilience(pce)
    assert pce._async_poll.__name__ == "_poll"
    # `pce.post` is a bound method, so a fresh object on every access -- identity
    # comparison never holds. Compare the underlying function instead.
    assert pce.post.__func__ is PolicyComputeEngine.post, "post must not be wrapped"
    assert "post" not in vars(pce), "nothing should be shadowing post on the instance"
