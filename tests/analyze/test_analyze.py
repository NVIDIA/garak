# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import json
import subprocess
import sys

import pytest

from garak import cli, _config
import garak.analyze
from garak.analyze.report_digest import build_digest

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


def test_analyze_log_zero_total_evaluated(tmp_path):
    """analyze_log must not crash on an eval record with total_evaluated == 0.

    A detector returning all-None scores yields passed == fails == 0, so the
    evaluator writes a valid eval record with total_evaluated == 0. The pass
    rate for such a record is reported as 0.0000 rather than raising."""
    from garak.analyze.analyze_log import analyze_log

    report_path = tmp_path / "zero_eval.report.jsonl"
    report_path.write_text(
        json.dumps(
            {
                "entry_type": "eval",
                "probe": "test.Blank",
                "detector": "always.Fail",
                "passed": 0,
                "total_evaluated": 0,
                "fails": 0,
                "total_processed": 3,
                "nones": 3,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    analyze_log(str(report_path))  # must not raise ZeroDivisionError


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


MOCK_REPORT = str(
    Path(__file__).parents[1] / "_assets" / "analyze" / "test.report.jsonl"
)


@pytest.fixture
def digest_config():
    config = _config.GarakSubConfig()
    config.reporting = _config.GarakSubConfig()
    config.reporting.taxonomy = None
    config.reporting.group_aggregation_function = "lower_quartile"
    config.reporting.show_100_pass_modules = True
    config.reporting.show_top_group_score = True
    return config


def test_build_digest_taxonomy_reflected_in_meta(digest_config):
    """When taxonomy is specified, digest meta.setup should reflect it."""
    digest_config.reporting.taxonomy = "avid-effect"
    digest = build_digest(MOCK_REPORT, config=digest_config)
    assert digest["meta"]["setup"]["reporting.taxonomy"] == "avid-effect"


def test_build_digest_no_taxonomy_reflected_as_none(digest_config):
    """When taxonomy is None, digest meta.setup should reflect None."""
    digest = build_digest(MOCK_REPORT, config=digest_config)
    assert digest["meta"]["setup"]["reporting.taxonomy"] is None


bound_constants = [c for c in dir(garak.analyze) if c.endswith("_BOUNDS")]


@pytest.mark.parametrize("constant_name", bound_constants)
def test_analyze_bound_members(constant_name):
    bounds = getattr(garak.analyze, constant_name)
    assert "TERRIBLE" in bounds.__members__
    assert "BELOW_AVG" in bounds.__members__
    assert "ABOVE_AVG" in bounds.__members__
    assert "EXCELLENT" in bounds.__members__
