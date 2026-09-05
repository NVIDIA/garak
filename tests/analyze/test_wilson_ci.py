# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import pytest

from garak.analyze.bootstrap_ci import apply_detector_correction
from garak.analyze.wilson_ci import calculate_wilson_ci, fallback_wilson_if_degenerate


@pytest.mark.parametrize(
    "successes,n,expected_lower_floor,expected_upper_ceil,description",
    [
        (10, 10, 70.0, 100.0, "perfect score"),
        (0, 10, 0.0, 30.0, "no successes"),
        (15, 30, 30.0, 70.0, "middle rate"),
    ],
)
def test_calculate_wilson_ci_bounds(
    successes, n, expected_lower_floor, expected_upper_ceil, description
):
    """Wilson intervals are within [0, 100] and nonzero at the boundary."""
    result = calculate_wilson_ci(successes, n)
    assert result is not None, description
    ci_lower, ci_upper = result
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100
    assert ci_lower <= ci_upper
    assert ci_lower >= expected_lower_floor
    assert ci_upper <= expected_upper_ceil
    assert ci_lower < ci_upper


def test_calculate_wilson_ci_boundary_values_match_known_intervals():
    """10/10 and 0/10 give the textbook [72%, 100%] and [0%, 28%] at 95%."""
    perfect = calculate_wilson_ci(10, 10)
    assert perfect is not None
    assert perfect[0] == pytest.approx(72.2, abs=0.5)
    assert perfect[1] == 100.0

    none_success = calculate_wilson_ci(0, 10)
    assert none_success is not None
    assert none_success[0] == pytest.approx(0.0, abs=1e-12)
    assert none_success[1] == pytest.approx(27.8, abs=0.5)


@pytest.mark.parametrize(
    "successes,n",
    [
        (0, 0),
        (1, 0),
        (-1, 10),
        (11, 10),
    ],
)
def test_calculate_wilson_ci_invalid_inputs(successes, n):
    assert calculate_wilson_ci(successes, n) is None


def test_calculate_wilson_ci_confidence_level_narrows_interval():
    wide = calculate_wilson_ci(15, 30, confidence_level=0.95)
    narrow = calculate_wilson_ci(15, 30, confidence_level=0.90)
    assert wide is not None and narrow is not None
    assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])


def test_fallback_wilson_if_degenerate():
    """A zero-width bootstrap interval is replaced by Wilson; others are kept."""
    ci_lower, ci_upper, method = fallback_wilson_if_degenerate(
        100.0, 100.0, successes=10, n=10
    )
    assert method == "wilson"
    assert ci_lower < ci_upper
    assert ci_lower >= 70.0
    assert ci_upper == 100.0

    ci_lower, ci_upper, method = fallback_wilson_if_degenerate(
        0.0, 0.0, successes=0, n=10
    )
    assert method == "wilson"
    assert ci_lower < ci_upper

    ci_lower, ci_upper, method = fallback_wilson_if_degenerate(
        10.0, 30.0, successes=5, n=10
    )
    assert method == "bootstrap"
    assert (ci_lower, ci_upper) == (10.0, 30.0)


def test_fallback_wilson_if_degenerate_none_inputs():
    assert fallback_wilson_if_degenerate(None, None, successes=5, n=10) == (
        None,
        None,
        "bootstrap",
    )


def test_fallback_wilson_if_degenerate_does_not_log(caplog):
    """The substitution must not log from the helper: the evaluator owns the
    user-facing message (with detector/probe context), and a helper-level
    warning trips the CI garak.log grep gate when tests exercise the
    calculator path."""
    with caplog.at_level(logging.WARNING, logger="garak.analyze.wilson_ci"):
        fallback_wilson_if_degenerate(100.0, 100.0, successes=10, n=10)
    assert not caplog.records


def test_apply_detector_correction_maps_bounds_onto_corrected_scale():
    """Raw Wilson bounds pass through the Se/Sp correction used by the bootstrap (#2033)."""
    # raw upper bound 27.75%; Se=0.85, Sp=0.99 → denominator 0.84
    corrected = apply_detector_correction((0.0, 27.75), 0.85, 0.99)
    assert corrected[0] == pytest.approx(0.0, abs=0.01)  # (0 - 0.01)/0.84 < 0 → clipped
    assert corrected[1] == pytest.approx(31.85, abs=0.05)  # (0.2775 - 0.01)/0.84

    # Se=0.90, Sp=0.85 → denominator 0.75
    corrected = apply_detector_correction((0.0, 27.75), 0.90, 0.85)
    assert corrected[1] == pytest.approx(17.00, abs=0.05)  # (0.2775 - 0.15)/0.75


def test_apply_detector_correction_keeps_bounds_when_denominator_tiny():
    """|Se+Sp-1| < 0.01 skips the correction, matching the bootstrap fallback."""
    assert apply_detector_correction((0.0, 27.8), 0.5, 0.5) == (0.0, 27.8)


def test_apply_detector_correction_clips_weak_detector_saturation():
    """Weak detectors push a range of observed rates past [0, 1]; bounds clip."""
    # Se=Sp=0.6 → denominator 0.2; raw 80%/90% both map above 1.0 and clip
    assert apply_detector_correction((80.0, 90.0), 0.6, 0.6) == (100.0, 100.0)


def test_fallback_wilson_if_degenerate_applies_detector_correction():
    """The Wilson fallback reports on the corrected ASR scale, matching bootstrap rows."""
    ci_lower, ci_upper, method = fallback_wilson_if_degenerate(
        0.0, 0.0, successes=0, n=10, sensitivity=0.90, specificity=0.85
    )
    assert method == "wilson"
    assert ci_lower == pytest.approx(0.0, abs=0.01)
    assert ci_upper == pytest.approx(17.00, abs=0.1)  # (0.2775 - 0.15)/0.75

    # default (perfect detector) keeps the raw Wilson bounds
    ci_lower, ci_upper, method = fallback_wilson_if_degenerate(
        0.0, 0.0, successes=0, n=10
    )
    assert method == "wilson"
    assert ci_upper == pytest.approx(27.8, abs=0.1)
