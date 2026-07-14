# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for evaluator base: get_z_rating and intent breakdown in eval rows."""

import json
from contextlib import contextmanager
from pathlib import Path

import pytest

import garak._config
import garak.analyze
import garak.attempt
import garak.evaluators.base


class _CalibrationStub:
    """Minimal calibration stub that raises on any call to defcon_and_comment."""

    def __init__(self, zscore):
        self._zscore = zscore

    def get_z_score(
        self, probe_module, probe_classname, detector_module, detector_classname, score
    ):
        return self._zscore

    def defcon_and_comment(self, *args, **kwargs):
        raise AssertionError("get_z_rating must not call defcon_and_comment")


def _make_evaluator(zscore):
    ev = garak.evaluators.base.Evaluator.__new__(garak.evaluators.base.Evaluator)
    ev.calibration = _CalibrationStub(zscore)
    return ev


@pytest.mark.parametrize("zscore", [-2.0, -0.5, 0.0, 0.5, 2.0])
def test_get_z_rating_returns_symbol(zscore):
    ev = _make_evaluator(zscore)
    returned_z, symbol = ev.get_z_rating("probe.Probe", "detector.Detector", 50)
    assert returned_z == zscore
    assert symbol in ev.SYMBOL_SET.values()


def test_get_z_rating_none_zscore():
    ev = _make_evaluator(None)
    returned_z, symbol = ev.get_z_rating("probe.Probe", "detector.Detector", 50)
    assert returned_z is None
    assert symbol == ""


class ThresholdEvaluator(garak.evaluators.base.Evaluator):
    """Evaluator that treats scores >= 0.5 as pass."""

    def test(self, test_value: float) -> bool:
        return test_value >= 0.5


@pytest.fixture(autouse=True)
def _config_loaded():
    garak._config.load_base_config()
    garak._config.transient.hitlogfile = None
    garak._config.plugins.probes["test"]["generations"] = 1


@contextmanager
def _capture_report(report_path: Path):
    previous_filename = getattr(garak._config.transient, "report_filename", None)
    previous_reportfile = getattr(garak._config.transient, "reportfile", None)
    try:
        garak._config.transient.report_filename = str(report_path)
        garak._config.transient.reportfile = open(
            report_path, "w", buffering=1, encoding="utf-8"
        )
        yield
    finally:
        if garak._config.transient.reportfile is not None:
            garak._config.transient.reportfile.close()
        garak._config.transient.hitlogfile = None
        garak._config.transient.report_filename = previous_filename
        garak._config.transient.reportfile = previous_reportfile


def _attempt_with(
    intent: str | None, detector_scores: dict[str, list[float | None]]
) -> garak.attempt.Attempt:
    attempt = garak.attempt.Attempt(
        prompt=garak.attempt.Message(text="prompt", lang="*"),
        probe_classname="test.IntentProbe",
        intent=intent,
    )
    generations = max(len(scores) for scores in detector_scores.values())
    attempt.outputs = [f"out-{i}" for i in range(generations)]
    attempt.detector_results = detector_scores
    return attempt


def _eval_rows(report_path: Path) -> list[dict]:
    rows = []
    for line in report_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if row.get("entry_type") == "eval":
            rows.append(row)
    return rows


def test_eval_row_includes_intents_breakdown(tmp_path):
    reportfile = tmp_path / "report.report.jsonl"
    with _capture_report(reportfile):
        evaluator = ThresholdEvaluator()
        attempts = [
            _attempt_with(intent="deception", detector_scores={"d.D": [0.9, 0.2]}),
            _attempt_with(intent="manipulation", detector_scores={"d.D": [0.1]}),
        ]
        evaluator.evaluate(attempts)

    rows = _eval_rows(reportfile)
    assert len(rows) == 1
    row = rows[0]
    assert row["intents"] == {
        "deception": {"passed": 1, "total_evaluated": 2, "nones": 0},
        "manipulation": {"passed": 0, "total_evaluated": 1, "nones": 0},
    }
    assert row["passed"] == 1
    assert row["total_evaluated"] == 3


def test_eval_row_omits_intents_when_all_null(tmp_path):
    reportfile = tmp_path / "report.report.jsonl"
    with _capture_report(reportfile):
        evaluator = ThresholdEvaluator()
        attempts = [_attempt_with(intent=None, detector_scores={"d.D": [0.9]})]
        evaluator.evaluate(attempts)

    row = _eval_rows(reportfile)[0]
    assert "intents" not in row


def test_eval_row_counts_distinct_prompts_probe_wide(tmp_path):
    pass


def test_eval_row_intents_buckets_none_scores(tmp_path):
    reportfile = tmp_path / "report.report.jsonl"
    with _capture_report(reportfile):
        evaluator = ThresholdEvaluator()
        attempts = [
            _attempt_with(intent="deception", detector_scores={"d.D": [0.9, None]})
        ]
        evaluator.evaluate(attempts)

    row = _eval_rows(reportfile)[0]
    assert row["intents"]["deception"] == {
        "passed": 1,
        "total_evaluated": 1,
        "nones": 1,
    }
    assert row["nones"] == 1


def test_eval_row_intents_scoped_per_detector(tmp_path):
    reportfile = tmp_path / "report.report.jsonl"
    with _capture_report(reportfile):
        evaluator = ThresholdEvaluator()
        attempts = [
            _attempt_with(
                intent="deception", detector_scores={"d.D1": [0.9], "d.D2": [0.2]}
            ),
            _attempt_with(intent="manipulation", detector_scores={"d.D1": [0.1]}),
            _attempt_with(intent="deception", detector_scores={"d.D2": [0.8]}),
        ]
        evaluator.evaluate(attempts)

    rows = {row["detector"]: row for row in _eval_rows(reportfile)}
    assert rows["d.D1"]["intents"] == {
        "deception": {"passed": 1, "total_evaluated": 1, "nones": 0},
        "manipulation": {"passed": 0, "total_evaluated": 1, "nones": 0},
    }
    assert rows["d.D1"]["total_evaluated"] == 2
    assert rows["d.D2"]["intents"] == {
        "deception": {"passed": 1, "total_evaluated": 2, "nones": 0}
    }
    assert "manipulation" not in rows["d.D2"]["intents"]
    assert rows["d.D2"]["total_evaluated"] == 2
