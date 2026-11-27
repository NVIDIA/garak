"""Regression tests for cancelling parallel probe attempts."""

import io
import json
from multiprocessing import TimeoutError
from unittest.mock import Mock, patch

import pytest

from garak import _config
from garak.probes.base import Probe


@pytest.fixture
def parallel_probe(monkeypatch):
    """Provide attempts, a report buffer and a pool without starting workers."""
    probe = Probe()
    probe.parallel_attempts = 2
    probe.max_workers = 2
    probe.generator = Mock(parallel_capable=True)
    attempts = [probe._mint_attempt("hello", seq) for seq in range(2)]
    monkeypatch.setattr(_config.transient, "reportfile", io.StringIO())
    with patch("multiprocessing.Pool") as factory:
        yield probe, attempts, factory.return_value


def test_attempt_wait_polls_and_preserves_reporting(parallel_probe):
    """Polling must retain unordered results and write each report entry once."""
    probe, attempts, pool = parallel_probe
    results = list(reversed(attempts))
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.return_value = iter(results)
    iterator.next.side_effect = [TimeoutError(), *results]

    completed = probe._execute_all(attempts)

    assert [a.uuid for a in completed] == [
        a.uuid for a in results
    ], "Every completed attempt must be retained"
    records = [
        json.loads(line)
        for line in _config.transient.reportfile.getvalue().splitlines()
    ]
    assert [record["uuid"] for record in records] == [
        str(a.uuid) for a in results
    ], "Every completed attempt must be reported once"
    assert iterator.next.call_count == 3, "A timeout must retry the result wait"
    for call in iterator.next.call_args_list:
        assert 0 < call.kwargs["timeout"] <= 1, "Attempt waits must be bounded"
    pool.imap_unordered.assert_called_once_with(probe._execute_attempt, attempts)
    pool.terminate.assert_not_called()
    pool.close.assert_called_once_with()
    pool.join.assert_called_once_with()


@pytest.mark.parametrize("completed_count", [0, 1])
def test_interrupt_terminates_pending_attempts(parallel_probe, completed_count):
    """Cancellation preserves reported attempts without waiting for other work."""
    probe, attempts, pool = parallel_probe
    partial = attempts[:completed_count]

    def interrupted_results():
        yield from partial
        raise KeyboardInterrupt

    iterator = pool.imap_unordered.return_value
    iterator.__iter__.side_effect = interrupted_results
    iterator.next.side_effect = [*partial, KeyboardInterrupt()]

    with pytest.raises(KeyboardInterrupt):
        probe._execute_all(attempts)

    assert (
        len(_config.transient.reportfile.getvalue().splitlines()) == completed_count
    ), "Previously completed attempts must remain in the report"
    pool.close.assert_not_called()
    pool.terminate.assert_called_once_with()
    pool.join.assert_called_once_with()
    assert [call[0] for call in pool.method_calls][-2:] == [
        "terminate",
        "join",
    ], "Workers must be terminated before joining"


def test_reporting_failure_terminates_pending_attempts(parallel_probe, monkeypatch):
    """A report write failure must not wait for outstanding requests."""
    probe, attempts, pool = parallel_probe
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.return_value = iter(attempts)
    iterator.next.side_effect = attempts
    monkeypatch.setattr(
        _config.transient.reportfile, "write", Mock(side_effect=OSError("disk full"))
    )

    with pytest.raises(OSError, match="disk full"):
        probe._execute_all(attempts)

    pool.close.assert_not_called()
    pool.terminate.assert_called_once_with()
    pool.join.assert_called_once_with()
