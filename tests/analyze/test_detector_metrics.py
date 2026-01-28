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

    se, sp = dm.get_detector_se_sp("dan.DAN")
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
    se, sp = dm.get_detector_se_sp("missing.Detector")
    assert se == 1.0
    assert sp == 1.0


def test_get_performance_strips_detector_prefix():
    """Test that 'detector.' prefix is stripped before lookup"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    test_se, test_sp = 0.90, 0.85
    dm._data = {
        "results": {
            "dan.DAN": {"metrics": {"hit_sensitivity": test_se, "hit_specificity": test_sp}}
        }
    }

    # Query with "detector." prefix
    se, sp = dm.get_detector_se_sp("detector.dan.DAN")
    assert se == test_se, "Should return sensitivity when queried with 'detector.' prefix"
    assert sp == test_sp, "Should return specificity when queried with 'detector.' prefix"

    # Query without prefix should give same result
    se2, sp2 = dm.get_detector_se_sp("dan.DAN")
    assert se == se2, "Results should be identical with or without 'detector.' prefix"
    assert sp == sp2, "Results should be identical with or without 'detector.' prefix"


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

    se, sp = dm.get_detector_se_sp("dan.DAN")
    assert se == 1.0, f"Should return default for {description}"
    assert sp == 1.0, f"Should return default for {description}"


def test_get_performance_multiple_detectors():
    """Test querying multiple detectors from same instance"""
    dm = garak.analyze.detector_metrics.DetectorMetrics()
    dm.metrics_loaded = True
    detector1_se, detector1_sp = 0.95, 0.74
    detector2_se, detector2_sp = 0.92, 0.86
    dm._data = {
        "results": {
            "dan.DAN": {"metrics": {"hit_sensitivity": detector1_se, "hit_specificity": detector1_sp}},
            "mitigation.MitigationBypass": {
                "metrics": {"hit_sensitivity": detector2_se, "hit_specificity": detector2_sp}
            },
        }
    }

    se1, sp1 = dm.get_detector_se_sp("dan.DAN")
    assert se1 == detector1_se, "Should return correct sensitivity for first detector"
    assert sp1 == detector1_sp, "Should return correct specificity for first detector"
    assert 0.0 <= se1 <= 1.0, "First detector sensitivity should be in valid range"
    assert 0.0 <= sp1 <= 1.0, "First detector specificity should be in valid range"

    se2, sp2 = dm.get_detector_se_sp("mitigation.MitigationBypass")
    assert se2 == detector2_se, "Should return correct sensitivity for second detector"
    assert sp2 == detector2_sp, "Should return correct specificity for second detector"
    assert 0.0 <= se2 <= 1.0, "Second detector sensitivity should be in valid range"
    assert 0.0 <= sp2 <= 1.0, "Second detector specificity should be in valid range"
    
    # Verify detectors are independent (different values)
    assert (se1, sp1) != (se2, sp2), "Different detectors should return independent values"


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

    se, sp = dm.get_detector_se_sp("bad.Detector")
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

    se, sp = dm.get_detector_se_sp(detector_name)
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
