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


def test_analyze_log_unscoreable_detector_scores(tmp_path, capsys):
    """analyze_log must not crash when an attempt reports unscoreable outputs.

    Detectors return None for outputs they cannot score, and those Nones are
    serialised into the attempt record's ``detector_results`` -- the same
    condition that makes the evaluator write ``nones`` with
    ``total_evaluated == 0``. Nothing here is a hit, so the attempt contributes
    no line and the rest of the report is still summarised."""
    from garak.analyze.analyze_log import analyze_log

    report_path = tmp_path / "all_unscoreable.report.jsonl"
    records = [
        {
            "entry_type": "attempt",
            "status": 1,
            "uuid": "u1",
            "probe_classname": "test.Test",
            "prompt": "p",
            "outputs": [None, None],
        },
        {
            "entry_type": "attempt",
            "status": 2,
            "uuid": "u1",
            "probe_classname": "test.Test",
            "prompt": "p",
            "outputs": [None, None],
            "detector_results": {"mitigation.MitigationBypass": [None, None]},
        },
        {
            "entry_type": "eval",
            "probe": "test.Test",
            "detector": "mitigation.MitigationBypass",
            "passed": 0,
            "fails": 0,
            "nones": 2,
            "total_evaluated": 0,
            "total_processed": 2,
        },
    ]
    report_path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )

    analyze_log(str(report_path))  # must not raise TypeError

    out = capsys.readouterr().out
    assert "100.00%" not in out, "an unscoreable attempt is not a hit"
    assert "## 1 attempts completed" in out
    assert "## attempt completion rate 100%" in out


def test_analyze_log_hit_rate_excludes_unscoreable_outputs(tmp_path, capsys):
    """A mixed attempt reports its hit rate over scored outputs only.

    ``detector_results`` align with ``outputs``, and None means the detector
    could not judge that output -- exactly what the evaluator leaves out of
    ``total_evaluated`` (see docs/source/reporting.rst). Treating those slots as
    misses would deflate the rate shown here."""
    from garak.analyze.analyze_log import analyze_log

    report_path = tmp_path / "mixed_unscoreable.report.jsonl"
    records = [
        {
            "entry_type": "attempt",
            "status": 1,
            "uuid": "u1",
            "probe_classname": "test.Test",
            "prompt": "p",
            "outputs": ["hit", "miss", None],
        },
        {
            "entry_type": "attempt",
            "status": 2,
            "uuid": "u1",
            "probe_classname": "test.Test",
            "prompt": "p",
            "outputs": ["hit", "miss", None],
            "detector_results": {"mitigation.MitigationBypass": [1.0, 0.0, None]},
        },
    ]
    report_path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )

    analyze_log(str(report_path))

    out = capsys.readouterr().out
    assert "50.00%" in out, "one hit over the two scored outputs"
    assert "33.33%" not in out, "the unscoreable slot must not deflate the rate"


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
