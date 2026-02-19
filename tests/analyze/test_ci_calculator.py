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


def test_calculate_ci_from_report_no_digest():
    """Verify error when report file missing digest entry"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        f.write(json.dumps({"entry_type": "init", "garak_version": "0.10"}) + "\n")
        f.write(json.dumps({"entry_type": "start_run setup", "run.eval_threshold": 0.5}) + "\n")
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(ValueError, match="missing 'digest' entry"):
            garak.analyze.ci_calculator.calculate_ci_from_report(str(temp_path))
    finally:
        temp_path.unlink()


def test_insufficient_samples():
    """Verify warning logged when n < bootstrap_min_sample_size"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        # Write minimal report with digest
        f.write(json.dumps({"entry_type": "init", "garak_version": "0.11"}) + "\n")
        f.write(json.dumps({"entry_type": "start_run setup", "run.eval_threshold": 0.5}) + "\n")
        
        # Digest with insufficient samples (n=10, minimum is 30 by default)
        digest = {
            "entry_type": "digest",
            "eval": {
                "test_group": {
                    "test.Test": {
                        "Detector": {
                            "total_evaluated": 10,
                            "passed": 3,
                            "score": 0.3
                        }
                    }
                }
            }
        }
        f.write(json.dumps(digest) + "\n")
        temp_path = Path(f.name)
    
    try:
        ci_results = garak.analyze.ci_calculator.calculate_ci_from_report(str(temp_path))
        # Should return empty dict due to insufficient samples
        assert len(ci_results) == 0
    finally:
        temp_path.unlink()


def test_calculate_ci_from_report_success():
    """Verify successful CI calculation from digest"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        f.write(json.dumps({"entry_type": "init", "garak_version": "0.11"}) + "\n")
        f.write(json.dumps({"entry_type": "start_run setup", "run.eval_threshold": 0.5}) + "\n")
        
        # Digest with sufficient samples (n=50)
        digest = {
            "entry_type": "digest",
            "eval": {
                "test_group": {
                    "encoding.InjectBase64": {
                        "mitigation.MitigationBypass": {
                            "total_evaluated": 50,
                            "passed": 37,
                            "score": 0.74
                        }
                    }
                }
            }
        }
        f.write(json.dumps(digest) + "\n")
        temp_path = Path(f.name)
    
    try:
        ci_results = garak.analyze.ci_calculator.calculate_ci_from_report(str(temp_path))
        
        # Should have one result
        assert len(ci_results) == 1
        
        # Check the key format
        key = list(ci_results.keys())[0]
        assert key[0] == "probes.encoding.InjectBase64"
        assert key[1] == "detector.mitigation.MitigationBypass"
        
        # Check CI bounds are reasonable (0-100 range)
        ci_lower, ci_upper = ci_results[key]
        assert 0 <= ci_lower <= 100
        assert 0 <= ci_upper <= 100
        assert ci_lower <= ci_upper
    finally:
        temp_path.unlink()


def test_update_eval_entries_with_ci():
    """Verify eval entries are updated with CI values"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        f.write(json.dumps({"entry_type": "init"}) + "\n")
        f.write(json.dumps({
            "entry_type": "eval",
            "probe": "probes.test.Test",
            "detector": "detector.test.Detector",
            "passed": 75,
            "total_evaluated": 100
        }) + "\n")
        temp_path = Path(f.name)
    
    try:
        ci_results = {
            ("probes.test.Test", "detector.test.Detector"): (65.2, 84.8)
        }
        
        output_path = temp_path.with_suffix('.updated.jsonl')
        garak.analyze.ci_calculator.update_eval_entries_with_ci(
            str(temp_path),
            ci_results,
            output_path=str(output_path)
        )
        
        # Read updated file
        with open(output_path, 'r') as f:
            lines = f.readlines()
            eval_entry = json.loads(lines[1])
            
            assert "confidence_lower" in eval_entry
            assert "confidence_upper" in eval_entry
            assert eval_entry["confidence_lower"] == pytest.approx(0.652, abs=0.001)
            assert eval_entry["confidence_upper"] == pytest.approx(0.848, abs=0.001)
            assert eval_entry["confidence_method"] == _config.reporting.confidence_interval_method
        
        output_path.unlink()
    finally:
        temp_path.unlink()
