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


def test_reconstruct_binary_results_success():
    """Verify binary result reconstruction from attempt records"""
    attempts = [{
        "entry_type": "attempt",
        "status": 2,
        "probe_classname": "test.Test",
        "detector_results": {"test.Detector": [0.3, 0.7, 0.4]}
    }]
    
    binary_results = garak.analyze.ci_calculator.reconstruct_binary_results(
        attempts=attempts,
        probe_name="test.Test",
        detector_name="test.Detector",
        eval_threshold=0.5
    )
    
    assert len(binary_results) == 3
    assert binary_results == [0, 1, 0]


def test_reconstruct_binary_results_no_match():
    """Verify error when no matching probe/detector found"""
    attempts = [{"status": 2, "probe_classname": "test.Test", "detector_results": {}}]
    
    with pytest.raises(ValueError, match="No results found"):
        garak.analyze.ci_calculator.reconstruct_binary_results(
            attempts, "test.Test", "nonexistent.Detector", 0.5
        )


def test_calculate_ci_from_report_file_not_found():
    """Verify error when report file doesn't exist"""
    with pytest.raises(FileNotFoundError, match="Report file not found"):
        garak.analyze.ci_calculator.calculate_ci_from_report("/nonexistent/report.jsonl")


def test_insufficient_samples():
    """Verify warning logged when n < bootstrap_min_sample_size"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        f.write(json.dumps({"entry_type": "start_run setup", "run.eval_threshold": 0.5}) + "\n")
        for i in range(10):
            f.write(json.dumps({"entry_type": "attempt", "status": 2, "probe_classname": "test.Test", "detector_results": {"test.D": [0.3]}}) + "\n")
        f.write(json.dumps({"entry_type": "eval", "probe": "test.Test", "detector": "test.D"}) + "\n")
        temp_path = Path(f.name)
    
    try:
        ci_results = garak.analyze.ci_calculator.calculate_ci_from_report(str(temp_path))
        assert len(ci_results) == 0
    finally:
        temp_path.unlink()
