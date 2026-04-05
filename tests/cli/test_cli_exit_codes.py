# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for CLI exit codes (issue #1221)."""

import pytest

from garak import cli
from garak.exception import ExitCode


class TestExitCodeEnum:
    """Verify the ExitCode enum values follow Unix conventions."""

    def test_success_is_zero(self):
        assert ExitCode.SUCCESS == 0

    def test_runtime_error_is_one(self):
        assert ExitCode.RUNTIME_ERROR == 1

    def test_usage_error_is_two(self):
        assert ExitCode.USAGE_ERROR == 2

    def test_config_error_is_three(self):
        assert ExitCode.CONFIG_ERROR == 3

    def test_plugin_error_is_four(self):
        assert ExitCode.PLUGIN_ERROR == 4

    def test_interrupted_is_five(self):
        assert ExitCode.INTERRUPTED == 5

    def test_exit_codes_are_ints(self):
        """ExitCode values can be passed directly to sys.exit()."""
        for code in ExitCode:
            assert isinstance(code, int)
            assert isinstance(int(code), int)


class TestMainReturnCodes:
    """Verify cli.main() returns appropriate exit codes."""

    def test_version_returns_success(self):
        result = cli.main(["--version"])
        assert result == ExitCode.SUCCESS

    def test_list_probes_returns_success(self):
        result = cli.main(["--list_probes"])
        assert result == ExitCode.SUCCESS

    def test_list_detectors_returns_success(self):
        result = cli.main(["--list_detectors"])
        assert result == ExitCode.SUCCESS

    def test_list_generators_returns_success(self):
        result = cli.main(["--list_generators"])
        assert result == ExitCode.SUCCESS

    def test_list_buffs_returns_success(self):
        result = cli.main(["--list_buffs"])
        assert result == ExitCode.SUCCESS

    def test_nothing_to_do_returns_success(self):
        result = cli.main([])
        assert result == ExitCode.SUCCESS

    def test_missing_config_file_returns_config_error(self):
        result = cli.main(["--config", "/nonexistent/path/config.yaml"])
        assert result == ExitCode.CONFIG_ERROR

    def test_bad_parallel_attempts_returns_usage_error(self):
        result = cli.main(["--parallel_attempts", "0"])
        assert result == ExitCode.USAGE_ERROR

    def test_bad_parallel_requests_returns_usage_error(self):
        result = cli.main(["--parallel_requests", "-1"])
        assert result == ExitCode.USAGE_ERROR

    def test_bad_bootstrap_iterations_returns_usage_error(self):
        result = cli.main(["--bootstrap_num_iterations", "-5"])
        assert result == ExitCode.USAGE_ERROR

    def test_bad_confidence_level_returns_usage_error(self):
        result = cli.main(["--bootstrap_confidence_level", "1.5"])
        assert result == ExitCode.USAGE_ERROR

    def test_return_type_is_int(self):
        result = cli.main(["--version"])
        assert isinstance(result, int)
