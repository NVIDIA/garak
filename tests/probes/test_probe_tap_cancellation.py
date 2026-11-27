"""Cancellation tests for the custom TAP-family attempt pools."""

from multiprocessing import TimeoutError
from unittest.mock import Mock, patch

import pytest

from garak.probes import tap


@pytest.fixture(params=[tap.TAP])
def parallel_probe(request):
    """Exercise attempt dispatch without running auxiliary attack targets."""
    probe = request.param()
    probe.parallel_attempts = 2
    probe.run_tap = Mock(return_value=["first prompt", "second prompt"])
    results = [
        probe._mint_attempt(prompt, seq)
        for seq, prompt in enumerate(probe.run_tap.return_value)
    ]
    with patch("multiprocessing.Pool") as factory:
        yield probe, results, factory.return_value


def test_custom_attempt_wait_polls_without_losing_results(parallel_probe):
    """A polling timeout must not rerun the attack search or drop attempts."""
    probe, results, pool = parallel_probe
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.return_value = iter(results)
    iterator.next.side_effect = [TimeoutError(), *results]

    completed = probe.probe(Mock())

    assert completed == results, "Every completed attempt must be returned"
    probe.run_tap.assert_called_once()
    pool.imap_unordered.assert_called_once()
    submitted = pool.imap_unordered.call_args.args[1]
    assert [attempt.prompt.last_message().text for attempt in submitted] == [
        "first prompt",
        "second prompt",
    ], "All generated prompts must be dispatched"
    assert iterator.next.call_count == 3, "A timeout must retry the result wait"
    for call in iterator.next.call_args_list:
        assert 0 < call.kwargs["timeout"] <= 1, "Attempt waits must be bounded"
    pool.terminate.assert_not_called()
    pool.close.assert_called_once_with()
    pool.join.assert_called_once_with()


@pytest.mark.parametrize("completed_count", [0, 1])
def test_custom_attempt_interrupt_terminates_workers(parallel_probe, completed_count):
    """Interrupting an attempt wait must stop remaining requests."""
    probe, results, pool = parallel_probe
    partial = results[:completed_count]

    def interrupted_results():
        yield from partial
        raise KeyboardInterrupt

    iterator = pool.imap_unordered.return_value
    iterator.__iter__.side_effect = interrupted_results
    iterator.next.side_effect = [*partial, KeyboardInterrupt()]

    with pytest.raises(KeyboardInterrupt):
        probe.probe(Mock())

    pool.close.assert_not_called()
    pool.terminate.assert_called_once_with()
    pool.join.assert_called_once_with()
    assert [call[0] for call in pool.method_calls][-2:] == [
        "terminate",
        "join",
    ], "Workers must be terminated before joining"


def test_custom_attempt_failure_terminates_workers(parallel_probe):
    """A failed worker must not leave other requests running."""
    probe, _, pool = parallel_probe
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.side_effect = RuntimeError("request failed")
    iterator.next.side_effect = RuntimeError("request failed")

    with pytest.raises(RuntimeError, match="request failed"):
        probe.probe(Mock())

    pool.close.assert_not_called()
    pool.terminate.assert_called_once_with()
    pool.join.assert_called_once_with()
