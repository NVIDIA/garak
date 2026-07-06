# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from garak import _config
import garak.analyze.report_digest
from garak.exception import ReportIncompatibleError


def _write_report_with_eval(tmp_path, eval_entry):
    report_path = tmp_path / "unknown_plugin.report.jsonl"
    with open(
        "tests/_assets/analyze/test.report.jsonl",
        encoding="utf-8",
    ) as f:
        setup_line = f.readline()
        init_line = f.readline()
    with open(report_path, "w", encoding="utf-8") as out:
        out.write(setup_line)
        out.write(init_line)
        out.write(json.dumps(eval_entry, ensure_ascii=False) + "\n")
    return str(report_path)


def test_build_digest_raises_on_unknown_probe(tmp_path) -> None:
    _config.load_base_config()
    _config.reporting.taxonomy = "owasp"
    eval_entry = {
        "entry_type": "eval",
        "probe": "does_not_exist.NoSuchProbe",
        "detector": "always.Pass",
        "passed": 1,
        "total_evaluated": 1,
        "fails": 0,
        "nones": 0,
        "total_processed": 1,
    }
    report_path = _write_report_with_eval(tmp_path, eval_entry)

    with pytest.raises(ReportIncompatibleError) as exc_info:
        garak.analyze.report_digest.build_digest(report_path)
    assert "does_not_exist.NoSuchProbe" in str(exc_info.value)


def test_build_digest_raises_on_unknown_detector(tmp_path) -> None:
    _config.load_base_config()
    _config.reporting.taxonomy = None
    eval_entry = {
        "entry_type": "eval",
        "probe": "test.Test",
        "detector": "does_not_exist.NoSuchDetector",
        "passed": 1,
        "total_evaluated": 1,
        "fails": 0,
        "nones": 0,
        "total_processed": 1,
    }
    report_path = _write_report_with_eval(tmp_path, eval_entry)

    with pytest.raises(ReportIncompatibleError) as exc_info:
        garak.analyze.report_digest.build_digest(report_path)
    assert "does_not_exist.NoSuchDetector" in str(exc_info.value)
