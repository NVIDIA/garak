# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
import pytest

from garak.analyze.perf_stats import build_score_dict, _normalize_name


def _create_report(path: Path, eval_records: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for record in eval_records:
            f.write(json.dumps(record) + "\n")


def test_normalize_name():
    assert (
        _normalize_name("garak.probes.encoding.Braille", "probes") == "encoding.Braille"
    )
    assert _normalize_name("probes.encoding.Braille", "probes") == "encoding.Braille"
    assert _normalize_name("encoding.Braille", "probes") == "encoding.Braille"

    assert (
        _normalize_name("garak.detectors.ansiescape.Escaped", "detectors")
        == "ansiescape.Escaped"
    )
    assert (
        _normalize_name("detectors.ansiescape.Escaped", "detectors")
        == "ansiescape.Escaped"
    )
    assert _normalize_name("ansiescape.Escaped", "detectors") == "ansiescape.Escaped"


def test_build_score_dict_normalizes_calibration_keys(tmp_path):
    report_file = tmp_path / "test.report.jsonl"
    records = [
        {
            "entry_type": "eval",
            "probe": "garak.probes.ansiescape.AnsiEscaped",
            "detector": "detectors.ansiescape.Escaped",
            "passed": 8,
            "total_evaluated": 10,
        },
        {
            "entry_type": "eval",
            "probe": "probes.goodside.WhoIsRiley",
            "detector": "garak.detectors.goodside.RileyIsnt",
            "passed": 5,
            "total_evaluated": 10,
        },
    ]
    _create_report(report_file, records)

    result = build_score_dict([str(report_file)])
    assert "ansiescape.AnsiEscaped/ansiescape.Escaped" in result
    assert "goodside.WhoIsRiley/goodside.RileyIsnt" in result

    entry = result["ansiescape.AnsiEscaped/ansiescape.Escaped"]
    assert entry["mu"] == pytest.approx(0.8)
    assert entry["sigma"] == pytest.approx(0.0)
    assert entry["sw_p"] is None  # only 1 sample, so Shapiro-Wilk is None


def test_build_score_dict_small_sample_size_returns_none_sw_p(tmp_path):
    report1 = tmp_path / "rep1.jsonl"
    report2 = tmp_path / "rep2.jsonl"
    records1 = [
        {
            "entry_type": "eval",
            "probe": "encoding.InjectBraille",
            "detector": "encoding.DecodeMatch",
            "passed": 4,
            "total_evaluated": 10,
        }
    ]
    records2 = [
        {
            "entry_type": "eval",
            "probe": "encoding.InjectBraille",
            "detector": "encoding.DecodeMatch",
            "passed": 6,
            "total_evaluated": 10,
        }
    ]
    _create_report(report1, records1)
    _create_report(report2, records2)

    result = build_score_dict([str(report1), str(report2)])
    key = "encoding.InjectBraille/encoding.DecodeMatch"
    assert key in result
    assert result[key]["mu"] == pytest.approx(0.5)
    assert result[key]["sw_p"] is None  # 2 samples is too small for Shapiro-Wilk


def test_build_score_dict_sufficient_samples_computes_shapiro(tmp_path):
    reports = []
    for i, pass_rate in enumerate([0.2, 0.5, 0.8, 0.6]):
        rep = tmp_path / f"rep_{i}.jsonl"
        _create_report(
            rep,
            [
                {
                    "entry_type": "eval",
                    "probe": "probe.A",
                    "detector": "detector.B",
                    "passed": int(pass_rate * 10),
                    "total_evaluated": 10,
                }
            ],
        )
        reports.append(str(rep))

    result = build_score_dict(reports)
    key = "probe.A/detector.B"
    assert key in result
    assert isinstance(result[key]["sw_p"], float)
    assert 0.0 <= result[key]["sw_p"] <= 1.0


def test_build_score_dict_metadata(tmp_path):
    rep = tmp_path / "rep.jsonl"
    _create_report(
        rep,
        [
            {
                "entry_type": "eval",
                "probe": "probe.A",
                "detector": "detector.B",
                "passed": 10,
                "total_evaluated": 10,
            }
        ],
    )
    result = build_score_dict([str(rep)])
    meta = result.get("garak_calibration_meta")
    assert meta is not None
    assert meta["filenames"] == [str(rep)]
    assert meta["date"].endswith("Z")
    assert "+00:00Z" not in meta["date"]


def test_build_score_dict_zero_evaluated_ignored(tmp_path, capsys):
    rep = tmp_path / "rep.jsonl"
    _create_report(
        rep,
        [
            {
                "entry_type": "eval",
                "probe": "probe.Zero",
                "detector": "detector.Zero",
                "passed": 0,
                "total_evaluated": 0,
            }
        ],
    )
    result = build_score_dict([str(rep)])
    assert "probe.Zero/detector.Zero" not in result
    captured = capsys.readouterr()
    assert "total tests was 0" in captured.out
