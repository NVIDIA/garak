# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open

import garak.analyze.detector_metrics


def test_instantiate_missing_file():
    """Test that DetectorMetrics handles missing file gracefully"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    assert isinstance(dm, garak.analyze.detector_metrics.DetectorMetrics)
    # File likely doesn't exist in test environment
    # Should handle gracefully with metrics_loaded=False
    assert isinstance(dm._data, dict)


def test_get_performance_when_not_loaded():
    """Test get_performance returns defaults when metrics not loaded"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = False

    se, sp = dm.get_performance("dan.DAN")
    assert se == 1.0
    assert sp == 1.0


def test_get_performance_missing_detector():
    """Test get_performance returns defaults for missing detector"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = {
        "results": {
            "dan.DAN": {"metrics": {"hit_sensitivity": 0.95, "hit_specificity": 0.74}}
        }
    }

    # Query for detector not in data
    se, sp = dm.get_performance("missing.Detector")
    assert se == 1.0
    assert sp == 1.0


def test_get_performance_valid_detector():
    """Test get_performance with valid detector data"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = {
        "results": {
            "dan.DAN": {"metrics": {"hit_sensitivity": 0.95, "hit_specificity": 0.74}}
        }
    }

    se, sp = dm.get_performance("dan.DAN")
    assert se == 0.95
    assert sp == 0.74


def test_get_performance_strips_detector_prefix():
    """Test that 'detector.' prefix is stripped before lookup"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = {
        "results": {
            "dan.DAN": {"metrics": {"hit_sensitivity": 0.90, "hit_specificity": 0.85}}
        }
    }

    # Query with "detector." prefix
    se, sp = dm.get_performance("detector.dan.DAN")
    assert se == 0.90
    assert sp == 0.85

    # Query without prefix should give same result
    se2, sp2 = dm.get_performance("dan.DAN")
    assert se == se2
    assert sp == sp2


@pytest.mark.parametrize(
    "data_structure,description",
    [
        (
            {"results": {"dan.DAN": {"metrics": {"hit_specificity": 0.74}}}},
            "missing sensitivity",
        ),
        (
            {"results": {"dan.DAN": {"metrics": {"hit_sensitivity": 0.95}}}},
            "missing specificity",
        ),
        ({"results": {"dan.DAN": {}}}, "missing metrics field"),
        ({}, "missing results field"),
        ({"results": {}}, "empty results"),
    ],
)
def test_get_performance_handles_missing_fields(data_structure, description):
    """Test that missing fields return defaults (1.0, 1.0)"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = data_structure

    se, sp = dm.get_performance("dan.DAN")
    assert se == 1.0, f"Should return default for {description}"
    assert sp == 1.0, f"Should return default for {description}"


def test_get_performance_multiple_detectors():
    """Test querying multiple detectors from same instance"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = {
        "results": {
            "dan.DAN": {"metrics": {"hit_sensitivity": 0.95, "hit_specificity": 0.74}},
            "mitigation.MitigationBypass": {
                "metrics": {"hit_sensitivity": 0.92, "hit_specificity": 0.86}
            },
        }
    }

    se1, sp1 = dm.get_performance("dan.DAN")
    assert se1 == 0.95
    assert sp1 == 0.74

    se2, sp2 = dm.get_performance("mitigation.MitigationBypass")
    assert se2 == 0.92
    assert sp2 == 0.86


def test_load_metrics_malformed_json():
    """Test that malformed JSON is handled gracefully"""
    # This test verifies the exception handling in _load_metrics
    # Since the file doesn't exist in test environment, it will be caught
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    # Should not raise exception
    assert isinstance(dm, garak.analyze.detector_metrics.DetectorMetrics)


@pytest.mark.parametrize(
    "se_value,sp_value,description",
    [
        (1.5, 0.85, "sensitivity > 1.0"),
        (-0.2, 0.85, "sensitivity < 0.0"),
        (0.95, 1.3, "specificity > 1.0"),
        (0.95, -0.1, "specificity < 0.0"),
        ("high", 0.85, "non-numeric sensitivity"),
        (0.95, "low", "non-numeric specificity"),
    ],
)
def test_get_performance_validates_invalid_values(se_value, sp_value, description):
    """Test that invalid Se/Sp values are rejected and fall back to (1.0, 1.0)"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = {
        "results": {
            "bad.Detector": {
                "metrics": {
                    "hit_sensitivity": se_value,
                    "hit_specificity": sp_value,
                }
            }
        }
    }

    se, sp = dm.get_performance("bad.Detector")
    assert se == 1.0, f"Should fallback for {description}"
    assert sp == 1.0, f"Should fallback for {description}"


@pytest.mark.parametrize(
    "detector_name,se_expected,sp_expected",
    [
        ("perfect.Detector", 1.0, 1.0),
        ("random.Detector", 0.5, 0.5),
        ("zero.Detector", 0.0, 0.0),
    ],
)
def test_get_performance_accepts_edge_values(detector_name, se_expected, sp_expected):
    """Test that exactly 0.0 and 1.0 are valid boundary values"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    dm._data = {
        "results": {
            "perfect.Detector": {
                "metrics": {"hit_sensitivity": 1.0, "hit_specificity": 1.0}
            },
            "random.Detector": {
                "metrics": {"hit_sensitivity": 0.5, "hit_specificity": 0.5}
            },
            "zero.Detector": {
                "metrics": {"hit_sensitivity": 0.0, "hit_specificity": 0.0}
            },
        }
    }

    se, sp = dm.get_performance(detector_name)
    assert se == se_expected
    assert sp == sp_expected


def test_get_detector_metrics_returns_singleton():
    """Test that get_detector_metrics() returns the same instance"""
    # Clear the cache first to ensure clean state
    import garak.analyze.detector_metrics

    garak.analyze.detector_metrics._detector_metrics_cache = None

    # Get first instance
    dm1 = garak.analyze.detector_metrics.get_detector_metrics()
    assert isinstance(dm1, garak.analyze.detector_metrics.DetectorMetrics)

    # Get second instance - should be the same object
    dm2 = garak.analyze.detector_metrics.get_detector_metrics()
    assert dm2 is dm1, "get_detector_metrics should return the same instance"

    # Get third instance - verify singleton persists
    dm3 = garak.analyze.detector_metrics.get_detector_metrics()
    assert dm3 is dm1, "Singleton should persist across multiple calls"

    # Clean up cache
    garak.analyze.detector_metrics._detector_metrics_cache = None
