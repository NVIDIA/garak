# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import garak.analyze.analyze_log


def test_analyze_log_zero_total_evaluated(tmp_path):
    """An eval record with total_evaluated == 0 must not raise ZeroDivisionError.

    total_evaluated is passes + fails, which is 0 when a probe/detector pair
    scored no evaluable outputs (all detector scores None). Every sibling
    analyzer guards this division.
    """
    report = tmp_path / "report.jsonl"
    report.write_text(
        json.dumps(
            {
                "entry_type": "eval",
                "probe": "test.Probe",
                "detector": "test.Detector",
                "passed": 0,
                "total_evaluated": 0,
                "total_processed": 0,
            }
        )
        + "\n"
    )
    garak.analyze.analyze_log.analyze_log(str(report))  # must not raise


def test_analyze_log_legacy_total_key(tmp_path):
    """Older reports use 'total' rather than 'total_evaluated'/'total_processed'."""
    report = tmp_path / "report.jsonl"
    report.write_text(
        json.dumps(
            {
                "entry_type": "eval",
                "probe": "test.Probe",
                "detector": "test.Detector",
                "passed": 3,
                "total": 5,
            }
        )
        + "\n"
    )
    garak.analyze.analyze_log.analyze_log(str(report))  # must not raise
