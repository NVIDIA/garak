# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for structured exit codes (issue #1221).

Verifies that cli.main() returns the correct integer exit code for each
execution path so that wrapping tools can distinguish failure modes without
parsing stderr output.
"""

import sys
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from garak import cli
from garak.exception import ExitCode


@contextmanager
def _mock_evaluators():
    """Inject a stub for garak.evaluators so tests run without heavy ML deps."""
    stub = MagicMock()
    with patch.dict(
        sys.modules, {"garak.evaluators": stub, "garak.evaluators.base": stub}
    ):
        yield stub


# ---------------------------------------------------------------------------
# ExitCode enum contract
# ---------------------------------------------------------------------------


class TestExitCodeEnum:
    def test_success_is_zero(self):
        assert int(ExitCode.SUCCESS) == 0

    def test_interrupted_is_minus_one(self):
        assert int(ExitCode.INTERRUPTED) == -1

    def test_probe_exception_is_minus_two(self):
        assert int(ExitCode.PROBE_EXCEPTION) == -2

    def test_generator_exception_is_minus_three(self):
        assert int(ExitCode.GENERATOR_EXCEPTION) == -3

    def test_detector_exception_is_minus_four(self):
        assert int(ExitCode.DETECTOR_EXCEPTION) == -4

    def test_buff_exception_is_minus_five(self):
        assert int(ExitCode.BUFF_EXCEPTION) == -5

    def test_evaluator_exception_is_minus_six(self):
        assert int(ExitCode.EVALUATOR_EXCEPTION) == -6

    def test_harness_exception_is_minus_seven(self):
        assert int(ExitCode.HARNESS_EXCEPTION) == -7

    def test_langprovider_exception_is_minus_eight(self):
        assert int(ExitCode.LANGPROVIDER_EXCEPTION) == -8

    def test_report_exception_is_minus_nine(self):
        assert int(ExitCode.REPORT_EXCEPTION) == -9

    def test_out_of_local_resources_is_minus_ten(self):
        assert int(ExitCode.OUT_OF_LOCAL_RESOURCES) == -10

    def test_unspecified_exception_is_minus_127(self):
        assert int(ExitCode.UNSPECIFIED_EXCEPTION) == -127

    def test_all_codes_are_int_compatible(self):
        for code in ExitCode:
            assert isinstance(int(code), int)


# ---------------------------------------------------------------------------
# cli.main() return type — must always return an int
# ---------------------------------------------------------------------------


class TestCliMainReturnType:
    def test_version_returns_int(self):
        with _mock_evaluators():
            result = cli.main(["--version"])
        assert isinstance(result, int)

    def test_list_probes_returns_int(self):
        with _mock_evaluators():
            result = cli.main(["--list_probes"])
        assert isinstance(result, int)

    def test_list_detectors_returns_int(self):
        with _mock_evaluators():
            result = cli.main(["--list_detectors"])
        assert isinstance(result, int)

    def test_list_generators_returns_int(self):
        with _mock_evaluators():
            result = cli.main(["--list_generators"])
        assert isinstance(result, int)

    def test_list_buffs_returns_int(self):
        with _mock_evaluators():
            result = cli.main(["--list_buffs"])
        assert isinstance(result, int)


# ---------------------------------------------------------------------------
# Success paths return ExitCode.SUCCESS (0)
# ---------------------------------------------------------------------------


class TestSuccessExitCodes:
    def test_version_is_success(self):
        with _mock_evaluators():
            assert cli.main(["--version"]) == int(ExitCode.SUCCESS)

    def test_list_probes_is_success(self):
        with _mock_evaluators():
            assert cli.main(["--list_probes"]) == int(ExitCode.SUCCESS)

    def test_list_detectors_is_success(self):
        with _mock_evaluators():
            assert cli.main(["--list_detectors"]) == int(ExitCode.SUCCESS)

    def test_list_generators_is_success(self):
        with _mock_evaluators():
            assert cli.main(["--list_generators"]) == int(ExitCode.SUCCESS)

    def test_list_buffs_is_success(self):
        with _mock_evaluators():
            assert cli.main(["--list_buffs"]) == int(ExitCode.SUCCESS)

    def test_no_args_is_success(self):
        with _mock_evaluators():
            assert cli.main([]) == int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# Error paths — config / arg validation failures (no evaluators needed)
# ---------------------------------------------------------------------------


class TestEarlyErrorExitCodes:
    """These errors occur before the main try block; evaluators are not imported."""

    def test_missing_config_file_returns_unspecified(self):
        result = cli.main(["--config", "/nonexistent/path/to/config.yaml"])
        assert result == int(ExitCode.UNSPECIFIED_EXCEPTION)

    def test_invalid_parallel_attempts_returns_unspecified(self):
        result = cli.main(["--parallel_attempts", "0"])
        assert result == int(ExitCode.UNSPECIFIED_EXCEPTION)

    def test_invalid_parallel_requests_returns_unspecified(self):
        result = cli.main(["--parallel_requests", "-1"])
        assert result == int(ExitCode.UNSPECIFIED_EXCEPTION)


# ---------------------------------------------------------------------------
# Error paths — exceptions inside the main try block
# ---------------------------------------------------------------------------


class TestMainTryExitCodes:
    """
    These tests raise exceptions from inside the main try block (after the
    evaluators import) by patching a function that is guaranteed to be called
    before any heavy model loading.
    """

    def test_keyboard_interrupt_returns_interrupted(self):
        with _mock_evaluators():
            with patch("garak.command.print_probes", side_effect=KeyboardInterrupt):
                result = cli.main(["--list_probes"])
        assert result == int(ExitCode.INTERRUPTED)

    def test_memory_error_returns_out_of_local_resources(self):
        with _mock_evaluators():
            with patch("garak.command.print_probes", side_effect=MemoryError("OOM")):
                result = cli.main(["--list_probes"])
        assert result == int(ExitCode.OUT_OF_LOCAL_RESOURCES)

    def test_garak_exception_returns_unspecified(self):
        from garak.exception import GarakException

        with _mock_evaluators():
            with patch(
                "garak.command.print_probes", side_effect=GarakException("test error")
            ):
                result = cli.main(["--list_probes"])
        assert result == int(ExitCode.UNSPECIFIED_EXCEPTION)

    def test_value_error_returns_unspecified(self):
        with _mock_evaluators():
            with patch(
                "garak.command.print_probes", side_effect=ValueError("bad value")
            ):
                result = cli.main(["--list_probes"])
        assert result == int(ExitCode.UNSPECIFIED_EXCEPTION)


# ---------------------------------------------------------------------------
# __main__ propagates the exit code to sys.exit
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    def test_main_calls_sys_exit_with_cli_return(self):
        """__main__.main() must pass cli.main()'s return value to sys.exit()."""
        import garak.__main__ as entrypoint

        with (
            patch.object(cli, "main", return_value=int(ExitCode.SUCCESS)),
            patch("sys.exit") as mock_exit,
            patch("sys.argv", ["garak", "--version"]),
        ):
            entrypoint.main()

        mock_exit.assert_called_once_with(int(ExitCode.SUCCESS))

    def test_main_propagates_error_exit_code(self):
        import garak.__main__ as entrypoint

        with (
            patch.object(cli, "main", return_value=int(ExitCode.UNSPECIFIED_EXCEPTION)),
            patch("sys.exit") as mock_exit,
            patch("sys.argv", ["garak", "--config", "/bad/path"]),
        ):
            entrypoint.main()

        mock_exit.assert_called_once_with(int(ExitCode.UNSPECIFIED_EXCEPTION))
