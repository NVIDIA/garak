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
    assert key[0] == "encoding.InjectBase64"
    assert key[1] == "mitigation.MitigationBypass"

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
            "probe": "test.Test",
            "detector": "test.Detector",
            "passed": 75,
            "total_evaluated": 100,
        },
    ])

    ci_results = {
        ("test.Test", "test.Detector"): (65.2, 84.8)
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
            "probe": "test.Test",
            "detector": "test.Detector",
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
            "probe": "test.Test",
            "detector": "test.Detector",
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
            "probe": "test.Test",
            "detector": "test.Detector",
            "confidence_method": "bootstrap",
            "confidence": "not_a_number",
        },
    ])

    result = garak.analyze.ci_calculator._extract_ci_config_from_report(str(report))
    assert result == {"confidence_method": "bootstrap"}
    assert "confidence_level" not in result


REBUILD_REPORT_ENTRIES = [
    {
        "entry_type": "init",
        "garak_version": "0.11",
        "start_time": "2026-01-01T00:00:00",
        "run": "test-run-uuid",
    },
    {
        "entry_type": "start_run setup",
        "reporting.confidence_interval_method": "bootstrap",
        "plugins.probe_spec": "encoding.InjectBase64",
        "plugins.target_type": "test",
        "plugins.target_name": "test-target",
    },
    {
        "entry_type": "eval",
        "probe": "encoding.InjectBase64",
        "detector": "mitigation.MitigationBypass",
        "passed": 37,
        "total_evaluated": 50,
        "fails": 13,
    },
    {
        "entry_type": "digest",
        "eval": {
            "test_group": {
                "encoding.InjectBase64": {
                    "mitigation.MitigationBypass": {
                        "total_evaluated": 50,
                        "passed": 37,
                        "score": 0.26,
                    }
                }
            }
        },
    },
]


def _assert_rebuilt_entries(target_path: Path) -> None:
    """Verify that a rebuilt report has CIs in eval entries and exactly one digest."""
    with open(target_path, "r") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    digests = [e for e in entries if e.get("entry_type") == "digest"]
    assert len(digests) == 1, f"Expected exactly 1 digest entry, found {len(digests)}"

    evals = [e for e in entries if e.get("entry_type") == "eval"]
    assert len(evals) >= 1
    for ev in evals:
        if ev.get("probe") == "encoding.InjectBase64":
            assert "confidence_lower" in ev, "eval entry should have CI after rebuild"
            assert "confidence_upper" in ev, "eval entry should have CI after rebuild"


def test_rebuild_cis_overwrite(temp_report, request):
    """rebuild_cis_for_report with overwrite=True modifies the original file."""
    from garak.analyze.rebuild_cis import rebuild_cis_for_report

    report = temp_report(REBUILD_REPORT_ENTRIES)
    original_content = report.read_text()

    _config.reporting.confidence_interval_method = "bootstrap"
    result = rebuild_cis_for_report(str(report), overwrite=True)
    assert result == 0

    assert report.read_text() != original_content, "Original file should be modified"
    _assert_rebuilt_entries(report)


def test_rebuild_cis_default_safe_output(temp_report, request):
    """rebuild_cis_for_report with no flags writes to .rebuilt file, original untouched."""
    from garak.analyze.rebuild_cis import rebuild_cis_for_report

    report = temp_report(REBUILD_REPORT_ENTRIES)
    original_content = report.read_text()

    name = report.name
    if name.endswith(".report.jsonl"):
        expected_name = name.removesuffix(".report.jsonl") + ".rebuilt.report.jsonl"
    else:
        expected_name = f"{report.stem}.rebuilt{report.suffix}"
    expected_output = report.parent / expected_name

    def cleanup_rebuilt():
        expected_output.unlink(missing_ok=True)

    request.addfinalizer(cleanup_rebuilt)

    _config.reporting.confidence_interval_method = "bootstrap"
    result = rebuild_cis_for_report(str(report))
    assert result == 0

    assert report.read_text() == original_content, "Original file should be untouched"
    assert expected_output.exists(), f"Expected rebuilt file at {expected_output}"
    _assert_rebuilt_entries(expected_output)


def test_rebuild_cis_explicit_output_path(temp_report, request, tmp_path):
    """rebuild_cis_for_report with output_path writes to the specified path."""
    from garak.analyze.rebuild_cis import rebuild_cis_for_report

    report = temp_report(REBUILD_REPORT_ENTRIES)
    original_content = report.read_text()
    custom_output = tmp_path / "custom_rebuilt.jsonl"

    _config.reporting.confidence_interval_method = "bootstrap"
    result = rebuild_cis_for_report(str(report), output_path=str(custom_output))
    assert result == 0

    assert report.read_text() == original_content, "Original file should be untouched"
    assert custom_output.exists(), f"Expected output at {custom_output}"
    _assert_rebuilt_entries(custom_output)


def test_rebuild_cis_mutually_exclusive_flags(temp_report, tmp_path):
    """Passing both output_path and overwrite=True returns error code 1."""
    from garak.analyze.rebuild_cis import rebuild_cis_for_report

    report = temp_report(REBUILD_REPORT_ENTRIES)
    custom_output = tmp_path / "should_not_exist.jsonl"

    _config.reporting.confidence_interval_method = "bootstrap"
    result = rebuild_cis_for_report(
        str(report), output_path=str(custom_output), overwrite=True
    )
    assert result == 1, "Should return 1 when both output_path and overwrite are set"
    assert not custom_output.exists(), "No output file should be created"


def test_extract_reporting_config_from_setup(temp_report):
    """Verify extraction of reporting.* keys from start_run setup entry."""
    report = temp_report([
        {
            "entry_type": "start_run setup",
            "reporting.taxonomy": None,
            "reporting.confidence_interval_method": "none",
            "reporting.bootstrap_confidence_level": 0.95,
            "plugins.target_type": "test",
            "system.verbose": 0,
        },
        {"entry_type": "init"},
    ])

    result = garak.analyze.ci_calculator._extract_reporting_config_from_setup(str(report))

    assert "reporting.confidence_interval_method" in result
    assert result["reporting.confidence_interval_method"] == "none"
    assert "reporting.bootstrap_confidence_level" in result
    assert result["reporting.bootstrap_confidence_level"] == 0.95
    assert "reporting.taxonomy" in result
    assert "plugins.target_type" not in result
    assert "system.verbose" not in result


def test_update_eval_entries_updates_start_run_setup(temp_report):
    """Verify update_eval_entries_with_ci updates reporting.* keys in start_run setup."""
    report = temp_report([
        {
            "entry_type": "start_run setup",
            "reporting.confidence_interval_method": "none",
            "reporting.bootstrap_num_iterations": 5000,
            "plugins.target_type": "test",
        },
        {
            "entry_type": "eval",
            "probe": "test.Test",
            "detector": "test.Detector",
            "passed": 75,
            "total_evaluated": 100,
        },
    ])

    ci_results = {
        ("test.Test", "test.Detector"): (65.2, 84.8)
    }

    output_path = report.with_suffix(".updated.jsonl")
    garak.analyze.ci_calculator.update_eval_entries_with_ci(
        str(report), ci_results, output_path=str(output_path)
    )

    with open(output_path, "r") as f:
        setup = json.loads(f.readline())

    assert setup["entry_type"] == "start_run setup"
    assert setup["reporting.confidence_interval_method"] == _config.reporting.confidence_interval_method
    assert setup["reporting.bootstrap_num_iterations"] == _config.reporting.bootstrap_num_iterations
    assert setup["reporting.bootstrap_confidence_level"] == _config.reporting.bootstrap_confidence_level

    output_path.unlink()


def test_update_preserves_non_reporting_setup_keys(temp_report):
    """Verify non-reporting keys in start_run setup are preserved unchanged."""
    report = temp_report([
        {
            "entry_type": "start_run setup",
            "plugins.target_type": "test",
            "plugins.probe_spec": "test.Test",
            "system.verbose": 0,
            "run.seed": 42,
            "reporting.confidence_interval_method": "none",
        },
        {"entry_type": "init"},
    ])

    ci_results = {}

    output_path = report.with_suffix(".updated.jsonl")
    garak.analyze.ci_calculator.update_eval_entries_with_ci(
        str(report), ci_results, output_path=str(output_path)
    )

    with open(output_path, "r") as f:
        setup = json.loads(f.readline())

    assert setup["plugins.target_type"] == "test"
    assert setup["plugins.probe_spec"] == "test.Test"
    assert setup["system.verbose"] == 0
    assert setup["run.seed"] == 42
    assert setup["entry_type"] == "start_run setup"

    output_path.unlink()
