# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pytest
from pathlib import Path
import tempfile

import garak.analyze.ci_calculator
from garak import _config


@pytest.fixture(autouse=True)
def _config_loaded():
    """Load base config for all tests in this module"""
    _config.load_base_config()


@pytest.fixture
def temp_report(request):
    """Create a temporary JSONL report file and ensure cleanup."""
    paths = []

    def _create(entries):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
        f.close()
        path = Path(f.name)
        paths.append(path)
        return path

    def cleanup():
        for p in paths:
            p.unlink(missing_ok=True)

    request.addfinalizer(cleanup)
    return _create


def test_reconstruct_binary_from_aggregates():
    """Verify binary reconstruction from passed/failed counts"""
    binary_results = garak.analyze.ci_calculator._reconstruct_binary_from_aggregates(
        passed=3, failed=2
    )

    assert len(binary_results) == 5
    assert binary_results.count(1) == 3
    assert binary_results.count(0) == 2
    assert binary_results == [1, 1, 1, 0, 0]


def test_reconstruct_binary_from_aggregates_all_passed():
    """Verify reconstruction when all samples passed"""
    binary_results = garak.analyze.ci_calculator._reconstruct_binary_from_aggregates(
        passed=5, failed=0
    )

    assert len(binary_results) == 5
    assert all(r == 1 for r in binary_results)


def test_reconstruct_binary_from_aggregates_all_failed():
    """Verify reconstruction when all samples failed"""
    binary_results = garak.analyze.ci_calculator._reconstruct_binary_from_aggregates(
        passed=0, failed=5
    )

    assert len(binary_results) == 5
    assert all(r == 0 for r in binary_results)


def test_calculate_ci_from_report_file_not_found():
    """Verify error when report file doesn't exist"""
    with pytest.raises(FileNotFoundError, match="Report file not found"):
        garak.analyze.ci_calculator.calculate_ci_from_report("/nonexistent/report.jsonl")


def test_calculate_ci_from_report_no_digest(temp_report):
    """Verify error when report file missing digest entry"""
    report = temp_report([
        {"entry_type": "init", "garak_version": "0.10"},
        {"entry_type": "start_run setup", "run.eval_threshold": 0.5},
    ])

    with pytest.raises(ValueError, match="missing 'digest' entry"):
        garak.analyze.ci_calculator.calculate_ci_from_report(str(report))


def test_insufficient_samples(temp_report):
    """Verify warning logged when n < bootstrap_min_sample_size"""
    report = temp_report([
        {"entry_type": "init", "garak_version": "0.11"},
        {"entry_type": "start_run setup", "run.eval_threshold": 0.5},
        {
            "entry_type": "digest",
            "eval": {
                "test_group": {
                    "test.Test": {
                        "Detector": {
                            "total_evaluated": 10,
                            "passed": 3,
                            "score": 0.3,
                        }
                    }
                }
            },
        },
    ])

    ci_results = garak.analyze.ci_calculator.calculate_ci_from_report(str(report))
    assert len(ci_results) == 0


def test_calculate_ci_from_report_success(temp_report):
    """Verify successful CI calculation from digest"""
    report = temp_report([
        {"entry_type": "init", "garak_version": "0.11"},
        {"entry_type": "start_run setup", "run.eval_threshold": 0.5},
        {
            "entry_type": "digest",
            "eval": {
                "test_group": {
                    "encoding.InjectBase64": {
                        "mitigation.MitigationBypass": {
                            "total_evaluated": 50,
                            "passed": 37,
                            "score": 0.74,
                        }
                    }
                }
            },
        },
    ])

    ci_results = garak.analyze.ci_calculator.calculate_ci_from_report(str(report))

    assert len(ci_results) == 1

    key = list(ci_results.keys())[0]
    assert key[0] == "probes.encoding.InjectBase64"
    assert key[1] == "detector.mitigation.MitigationBypass"

    ci_lower, ci_upper = ci_results[key]
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100
    assert ci_lower <= ci_upper


def test_update_eval_entries_with_ci(temp_report):
    """Verify eval entries are updated with CI values"""
    report = temp_report([
        {"entry_type": "init"},
        {
            "entry_type": "eval",
            "probe": "probes.test.Test",
            "detector": "detector.test.Detector",
            "passed": 75,
            "total_evaluated": 100,
        },
    ])

    ci_results = {
        ("probes.test.Test", "detector.test.Detector"): (65.2, 84.8)
    }

    output_path = report.with_suffix(".updated.jsonl")
    garak.analyze.ci_calculator.update_eval_entries_with_ci(
        str(report),
        ci_results,
        output_path=str(output_path),
    )

    with open(output_path, "r") as f:
        lines = f.readlines()
        eval_entry = json.loads(lines[1])

        assert "confidence_lower" in eval_entry
        assert "confidence_upper" in eval_entry
        assert eval_entry["confidence_lower"] == pytest.approx(0.652, abs=0.001)
        assert eval_entry["confidence_upper"] == pytest.approx(0.848, abs=0.001)
        assert eval_entry["confidence_method"] == _config.reporting.confidence_interval_method

    output_path.unlink()


def test_extract_ci_config_from_report_with_cis(temp_report):
    """Verify extraction of method and confidence level from report with existing CIs"""
    report = temp_report([
        {"entry_type": "init"},
        {
            "entry_type": "eval",
            "probe": "probes.test.Test",
            "detector": "detector.test.Detector",
            "confidence_method": "bootstrap",
            "confidence": "0.95",
            "confidence_lower": 0.65,
            "confidence_upper": 0.85,
        },
    ])

    result = garak.analyze.ci_calculator._extract_ci_config_from_report(str(report))
    assert result["confidence_method"] == "bootstrap"
    assert result["confidence_level"] == pytest.approx(0.95)


def test_extract_ci_config_from_report_no_cis(temp_report):
    """Verify empty dict returned when report has no CI data"""
    report = temp_report([
        {"entry_type": "init"},
        {
            "entry_type": "eval",
            "probe": "probes.test.Test",
            "detector": "detector.test.Detector",
            "passed": 75,
            "total_evaluated": 100,
        },
    ])

    result = garak.analyze.ci_calculator._extract_ci_config_from_report(str(report))
    assert result == {}


def test_extract_ci_config_from_report_malformed_confidence(temp_report):
    """Verify graceful handling when confidence field is not a valid float"""
    report = temp_report([
        {"entry_type": "init"},
        {
            "entry_type": "eval",
            "probe": "probes.test.Test",
            "detector": "detector.test.Detector",
            "confidence_method": "bootstrap",
            "confidence": "not_a_number",
        },
    ])

    result = garak.analyze.ci_calculator._extract_ci_config_from_report(str(report))
    assert result == {"confidence_method": "bootstrap"}
    assert "confidence_level" not in result
