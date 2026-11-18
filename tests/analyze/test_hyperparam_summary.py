# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import pytest

from garak.analyze.hyperparam_summary import summarise, main


def _write_report(path: pathlib.Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _attempt(combo: dict, detector_results: dict, status: int = 2) -> dict:
    return {
        "entry_type": "attempt",
        "status": status,
        "notes": {"hyperparam_combo": combo},
        "detector_results": detector_results,
    }


# ---------------------------------------------------------------------------
# summarise — basic tallying
# ---------------------------------------------------------------------------


def test_summarise_single_combo(tmp_path, capsys):
    """Single combo; counts and rate are correct."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [
            _attempt({"temperature": 0.5}, {"det1": [0.0, 1.0, 1.0]}),
        ],
    )
    summarise(report)
    out = capsys.readouterr().out
    assert "2/3" in out
    assert "67%" in out


def test_summarise_multiple_combos(tmp_path, capsys):
    """Multiple combos are listed separately with correct tallies."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [
            _attempt({"temperature": 0.0}, {"det1": [0.0, 0.0]}),
            _attempt({"temperature": 1.5}, {"det1": [1.0, 1.0]}),
        ],
    )
    summarise(report)
    out = capsys.readouterr().out
    assert "0/2" in out  # temperature 0.0 — no failures
    assert "2/2" in out  # temperature 1.5 — all failures


def test_summarise_threshold_boundary(tmp_path, capsys):
    """Score exactly 0.5 counts as failure (>= 0.5 threshold)."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [
            _attempt({"temperature": 1.0}, {"det1": [0.5, 0.49]}),
        ],
    )
    summarise(report)
    out = capsys.readouterr().out
    # 0.5 is a failure, 0.49 is not → 1/2
    assert "1/2" in out


# ---------------------------------------------------------------------------
# summarise — edge cases
# ---------------------------------------------------------------------------


def test_summarise_no_attempts(tmp_path, capsys):
    """Report with no matching attempts prints a clear message."""
    report = tmp_path / "run.report.jsonl"
    # Only non-attempt records
    _write_report(report, [{"entry_type": "init"}, {"entry_type": "setup"}])
    summarise(report)
    out = capsys.readouterr().out
    assert "No HyperparamBasher attempts found" in out


def test_summarise_non_complete_attempts_skipped(tmp_path, capsys):
    """Attempts with status != 2 are ignored."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [
            _attempt({"temperature": 0.5}, {"det1": [1.0]}, status=1),
        ],
    )
    summarise(report)
    out = capsys.readouterr().out
    assert "No HyperparamBasher attempts found" in out


def test_summarise_no_combo_key_skipped(tmp_path, capsys):
    """Attempts without hyperparam_combo note are silently skipped."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [
            {
                "entry_type": "attempt",
                "status": 2,
                "notes": {},
                "detector_results": {"det1": [1.0]},
            }
        ],
    )
    summarise(report)
    out = capsys.readouterr().out
    assert "No HyperparamBasher attempts found" in out


def test_summarise_empty_detector_results_warns(tmp_path, capsys):
    """All attempts having empty detector_results triggers a warning."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [
            _attempt({"temperature": 0.5}, {}),
        ],
    )
    summarise(report)
    out = capsys.readouterr().out
    assert "Warning" in out
    assert "detector_results" in out


def test_summarise_blank_lines_ignored(tmp_path, capsys):
    """Blank lines in the report file do not cause errors."""
    report = tmp_path / "run.report.jsonl"
    with report.open("w", encoding="utf-8") as f:
        f.write("\n")
        f.write(json.dumps(_attempt({"temperature": 0.5}, {"det1": [1.0]})) + "\n")
        f.write("\n")
    summarise(report)
    out = capsys.readouterr().out
    assert "1/1" in out


# ---------------------------------------------------------------------------
# main — CLI interface
# ---------------------------------------------------------------------------


def test_main_missing_report_exits(tmp_path):
    """main() exits with code 1 when the report file does not exist."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--report", str(tmp_path / "nonexistent.jsonl")])
    assert exc_info.value.code == 1


def test_main_requires_report_argument():
    """main() exits when --report is not supplied."""
    with pytest.raises(SystemExit):
        main([])


def test_main_runs_summarise(tmp_path, capsys):
    """main() with a valid report path calls summarise and prints output."""
    report = tmp_path / "run.report.jsonl"
    _write_report(
        report,
        [_attempt({"temperature": 0.5}, {"det1": [1.0, 0.0]})],
    )
    main(["--report", str(report)])
    out = capsys.readouterr().out
    assert "per-combo detection summary" in out
