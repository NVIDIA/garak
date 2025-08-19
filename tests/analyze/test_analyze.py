# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import subprocess
import sys

import pytest

from garak import cli, _config

TEMP_PREFIX = "_garak_internal_test_temp"


@pytest.fixture(autouse=True)
def garak_tiny_run() -> None:
    cli.main(["-m", "test.Blank", "-p", "test.Blank", "--report_prefix", TEMP_PREFIX])


def test_analyze_log_runs():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.analyze_log",
            str(
                _config.transient.data_dir
                / _config.reporting.report_dir
                / f"{TEMP_PREFIX}.report.jsonl"
            ),
        ],
        check=True,
    )
    assert result.returncode == 0


def test_report_digest_runs():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.report_digest",
            "-r",
            str(
                _config.transient.data_dir
                / _config.reporting.report_dir
                / f"{TEMP_PREFIX}.report.jsonl"
            ),
        ],
        check=True,
    )
    assert result.returncode == 0
