# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the _worker_logging_init pool initializer that prevents log-file
race conditions under parallel probe execution (issue #1355)."""

import logging
import os
import tempfile
from multiprocessing import Pool
from unittest.mock import MagicMock, patch

import pytest

import garak._config
import garak._plugins
import garak.attempt
from garak.probes.base import _worker_logging_init


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _log_from_worker(log_file: str) -> int:
    """Target function run inside a Pool worker.

    Returns the file-descriptor number of the root logger's FileHandler so the
    parent can verify each worker got its own private fd.
    """
    for i in range(50):
        logging.debug("worker log line %d", i)
    root = logging.getLogger()
    for h in root.handlers:
        if isinstance(h, logging.FileHandler):
            return h.stream.fileno()
    return -1


# ---------------------------------------------------------------------------
# Unit tests for _worker_logging_init
# ---------------------------------------------------------------------------


def test_worker_init_clears_inherited_handlers():
    """_worker_logging_init must remove all handlers the parent process had."""
    root = logging.getLogger()
    original_handlers = root.handlers[:]

    mock_handler = MagicMock(spec=logging.Handler)
    root.addHandler(mock_handler)
    assert mock_handler in root.handlers

    try:
        _worker_logging_init()
        assert mock_handler not in root.handlers, (
            "_worker_logging_init should remove all inherited handlers"
        )
    finally:
        # Restore whatever was there before (mock already removed by init)
        for h in root.handlers[:]:
            root.removeHandler(h)
        for h in original_handlers:
            root.addHandler(h)


def test_worker_init_opens_file_handler_when_env_set():
    """_worker_logging_init must install a FileHandler pointing at GARAK_LOG_FILE."""
    root = logging.getLogger()
    original_handlers = root.handlers[:]

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    old_env = os.environ.get("GARAK_LOG_FILE")
    os.environ["GARAK_LOG_FILE"] = log_path

    try:
        # Clear handlers so basicConfig will take effect
        for h in root.handlers[:]:
            root.removeHandler(h)

        _worker_logging_init()

        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) >= 1, (
            "_worker_logging_init should add a FileHandler when GARAK_LOG_FILE is set"
        )
        assert any(h.baseFilename == log_path for h in file_handlers), (
            "FileHandler should point at GARAK_LOG_FILE"
        )
    finally:
        for h in root.handlers[:]:
            if isinstance(h, logging.FileHandler):
                h.close()
            root.removeHandler(h)
        for h in original_handlers:
            root.addHandler(h)
        if old_env is None:
            os.environ.pop("GARAK_LOG_FILE", None)
        else:
            os.environ["GARAK_LOG_FILE"] = old_env
        os.unlink(log_path)


def test_worker_init_no_file_handler_when_env_unset():
    """_worker_logging_init must not add a FileHandler when GARAK_LOG_FILE is absent."""
    root = logging.getLogger()
    original_handlers = root.handlers[:]

    old_env = os.environ.pop("GARAK_LOG_FILE", None)

    try:
        for h in root.handlers[:]:
            root.removeHandler(h)

        _worker_logging_init()

        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert file_handlers == [], (
            "_worker_logging_init should not add a FileHandler when GARAK_LOG_FILE is not set"
        )
    finally:
        for h in root.handlers[:]:
            if isinstance(h, logging.FileHandler):
                h.close()
            root.removeHandler(h)
        for h in original_handlers:
            root.addHandler(h)
        if old_env is not None:
            os.environ["GARAK_LOG_FILE"] = old_env


def test_worker_init_is_idempotent():
    """Calling _worker_logging_init twice must not accumulate extra handlers."""
    root = logging.getLogger()
    original_handlers = root.handlers[:]

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    old_env = os.environ.get("GARAK_LOG_FILE")
    os.environ["GARAK_LOG_FILE"] = log_path

    try:
        for h in root.handlers[:]:
            root.removeHandler(h)

        _worker_logging_init()
        count_after_first = len(root.handlers)
        _worker_logging_init()
        count_after_second = len(root.handlers)

        assert count_after_second <= count_after_first, (
            "Calling _worker_logging_init twice must not add duplicate handlers"
        )
    finally:
        for h in root.handlers[:]:
            if isinstance(h, logging.FileHandler):
                h.close()
            root.removeHandler(h)
        for h in original_handlers:
            root.addHandler(h)
        if old_env is None:
            os.environ.pop("GARAK_LOG_FILE", None)
        else:
            os.environ["GARAK_LOG_FILE"] = old_env
        os.unlink(log_path)


# ---------------------------------------------------------------------------
# Integration test: parallel workers log without RuntimeError
# ---------------------------------------------------------------------------


def test_parallel_workers_log_without_error():
    """Pool workers initialised with _worker_logging_init must not raise
    RuntimeError due to shared-fd log writes (regression for issue #1355)."""
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    root = logging.getLogger()
    parent_handler = logging.FileHandler(log_path)
    root.addHandler(parent_handler)

    old_env = os.environ.get("GARAK_LOG_FILE")
    os.environ["GARAK_LOG_FILE"] = log_path

    errors = []
    try:
        with Pool(processes=4, initializer=_worker_logging_init) as pool:
            results = pool.map(_log_from_worker, [log_path] * 8)
        # All workers should have returned a valid fd number
        assert all(isinstance(r, int) for r in results), (
            "All worker tasks should complete and return an integer fd"
        )
    except RuntimeError as exc:
        errors.append(str(exc))
    finally:
        parent_handler.close()
        root.removeHandler(parent_handler)
        if old_env is None:
            os.environ.pop("GARAK_LOG_FILE", None)
        else:
            os.environ["GARAK_LOG_FILE"] = old_env
        os.unlink(log_path)

    assert not errors, (
        f"Parallel logging raised RuntimeError (race condition): {errors}"
    )


def test_parallel_worker_fds_are_independent():
    """Each Pool worker should open its own file descriptor for the log file,
    not share the parent's inherited fd (regression for issue #1355)."""
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    root = logging.getLogger()
    parent_handler = logging.FileHandler(log_path)
    root.addHandler(parent_handler)
    parent_fd = parent_handler.stream.fileno()

    old_env = os.environ.get("GARAK_LOG_FILE")
    os.environ["GARAK_LOG_FILE"] = log_path

    try:
        with Pool(processes=2, initializer=_worker_logging_init) as pool:
            worker_fds = pool.map(_log_from_worker, [log_path] * 2)

        # Workers that got a FileHandler should report a valid fd
        valid_fds = [fd for fd in worker_fds if fd != -1]
        if valid_fds:
            assert all(fd != parent_fd for fd in valid_fds), (
                "Worker file descriptors must differ from the parent's fd — "
                "shared fds cause the reentrant-flush race condition"
            )
    finally:
        parent_handler.close()
        root.removeHandler(parent_handler)
        if old_env is None:
            os.environ.pop("GARAK_LOG_FILE", None)
        else:
            os.environ["GARAK_LOG_FILE"] = old_env
        os.unlink(log_path)


# ---------------------------------------------------------------------------
# Regression test: Probe._execute_all must wire up the initializer
# ---------------------------------------------------------------------------


def test_execute_all_passes_logging_initializer_to_pool():
    """Probe._execute_all must construct its worker Pool with
    initializer=_worker_logging_init. Without this wiring, forked workers
    inherit the parent's log FileHandler and share its file descriptor,
    which can raise a reentrant-flush RuntimeError under concurrent writes
    (issue #1355). This test fails if the initializer argument is removed."""
    with open(os.devnull, "w+", encoding="utf-8") as fh:
        garak._config.load_base_config()
        garak._config.transient.reportfile = fh

        p = garak._plugins.load_plugin(
            "probes.test.Test", config_root=garak._config
        )
        g = garak._plugins.load_plugin(
            "generators.test.Repeat", config_root=garak._config
        )
        p.generator = g
        p.parallel_attempts = 2

        attempts = [
            garak.attempt.Attempt(prompt=garak.attempt.Message("test one")),
            garak.attempt.Attempt(prompt=garak.attempt.Message("test two")),
        ]

        real_pool = Pool

        with patch("multiprocessing.Pool", wraps=real_pool) as mock_pool:
            p._execute_all(attempts)

        garak._config.transient.reportfile = None

        assert mock_pool.called, "Probe._execute_all should use a worker Pool"
        _, kwargs = mock_pool.call_args
        assert kwargs.get("initializer") is _worker_logging_init, (
            "Probe._execute_all must pass _worker_logging_init as the Pool "
            "initializer to avoid shared log file descriptors in workers"
        )
