# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import numpy as np

import garak.analyze.bootstrap_ci
from garak import _config


@pytest.mark.parametrize(
    "results,should_succeed,description",
    [
        ([], False, "empty results"),
        ([0] * 15 + [1] * 5, False, "n=20 < 30"),
        ([0] * 20 + [1] * 9, False, "n=29 < 30"),
        ([0] * 20 + [1] * 10, True, "n=30 boundary"),
    ],
)
def test_calculate_bootstrap_ci_sample_size_threshold(
    results, should_succeed, description
):
    """Test sample size requirements for CI calculation"""
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=1.0, specificity=1.0
    )

    if should_succeed:
        assert result is not None, f"Should succeed for {description}"
        ci_lower, ci_upper = result
        assert 0 <= ci_lower <= 100
        assert 0 <= ci_upper <= 100
    else:
        assert result is None, f"Should return None for {description}"


def test_calculate_bootstrap_ci_perfect_detector():
    """Test CI calculation with perfect detector (Se=1.0, Sp=1.0)"""
    # 80 passes, 20 fails (20% fail rate)
    results = [0] * 80 + [1] * 20
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=1.0, specificity=1.0
    )
    assert result is not None
    ci_lower, ci_upper = result

    # CI should be within [0, 100]
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100

    # Lower should be less than upper
    assert ci_lower < ci_upper

    # With 80% pass rate (20% fail rate), CI should be reasonable
    assert ci_lower < 30  # Failrate is 20%, so lower bound should be below 30
    assert ci_upper > 10  # Upper bound should be above 10


def test_calculate_bootstrap_ci_imperfect_detector():
    """Test CI calculation with imperfect detector"""
    # 50 passes, 50 fails (50% fail rate)
    results = [0] * 50 + [1] * 50
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=0.9, specificity=0.85
    )
    assert result is not None
    ci_lower, ci_upper = result

    # CI should be within [0, 100]
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100

    # Lower should be less than upper
    assert ci_lower < ci_upper


@pytest.mark.parametrize(
    "results,se,sp,expected_lower_range,expected_upper_range,description",
    [
        ([0] * 50, 1.0, 1.0, (0, 0), (0, 10), "100% pass rate"),
        ([1] * 50, 1.0, 1.0, (90, 100), (100, 100), "100% fail rate"),
        ([0] * 2 + [1] * 48, 0.5, 0.5, (0, 100), (0, 100), "extreme metrics"),
    ],
)
def test_calculate_bootstrap_ci_extreme_cases(
    results, se, sp, expected_lower_range, expected_upper_range, description
):
    """Test CI calculation with extreme success rates and detector metrics"""
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=se, specificity=sp
    )
    assert result is not None, f"Should calculate CI for {description}"
    ci_lower, ci_upper = result

    # CI bounds must be within [0, 100]
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100

    # Check expected ranges
    assert (
        expected_lower_range[0] <= ci_lower <= expected_lower_range[1]
    ), f"Lower bound wrong for {description}"
    assert (
        expected_upper_range[0] <= ci_upper <= expected_upper_range[1]
    ), f"Upper bound wrong for {description}"


def test_calculate_bootstrap_ci_small_denominator_fallback():
    """Test fallback when Se+Sp-1 is too small"""
    # Se + Sp - 1 = 0.50 + 0.49 - 1 = -0.01, which is < 0.01
    # 40 passes, 40 fails (50% fail rate)
    results = [0] * 40 + [1] * 40
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=0.50, specificity=0.49
    )
    assert result is not None
    # Should fall back to uncorrected CI (perfect detector)
    ci_lower, ci_upper = result
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100


def test_calculate_bootstrap_ci_reproducibility():
    """Test that results are reproducible with seed"""
    # 60 passes, 40 fails (40% fail rate)
    results = [0] * 60 + [1] * 40

    # Set seed
    _config.run.seed = 42

    result1 = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=0.95, specificity=0.90
    )

    # Reset seed to same value
    _config.run.seed = 42

    result2 = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=0.95, specificity=0.90
    )

    assert result1 is not None and result2 is not None
    assert result1[0] == result2[0], "Lower bounds should match with same seed"
    assert result1[1] == result2[1], "Upper bounds should match with same seed"

    # Clean up
    _config.run.seed = None


def test_calculate_bootstrap_ci_custom_iterations():
    """Test with custom number of iterations"""
    # 70 passes, 30 fails (30% fail rate)
    results = [0] * 70 + [1] * 30
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results,
        sensitivity=1.0,
        specificity=1.0,
        num_iterations=1000,  # Fewer iterations for speed
    )
    assert result is not None
    ci_lower, ci_upper = result
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100


def test_calculate_bootstrap_ci_with_imperfect_metrics():
    """Test bootstrap with moderate detector metrics"""
    # 25 passes, 25 fails (50% fail rate)
    # Se=0.8, Sp=0.7 gives denominator=0.5 which is valid
    results = [0] * 25 + [1] * 25
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=0.8, specificity=0.7
    )
    assert result is not None
    ci_lower, ci_upper = result
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100


def test_nonparametric_vs_parametric_advantage():
    """Test that non-parametric bootstrap handles actual data distribution

    Non-parametric bootstrap resamples from actual data, so it correctly
    captures the empirical distribution without assuming it's binomial.
    This is especially important when results might be clustered or have
    other structure that violates independence assumptions.
    """
    # Create data with same overall fail rate but test with actual resampling
    # 30 passes, 20 fails (40% fail rate)
    results = [0] * 30 + [1] * 20

    # With perfect detector, CI should reflect only sampling uncertainty
    result = garak.analyze.bootstrap_ci.calculate_bootstrap_ci(
        results=results, sensitivity=1.0, specificity=1.0
    )
    assert result is not None
    ci_lower, ci_upper = result

    # CI should be reasonable for n=50
    assert 0 <= ci_lower <= 100
    assert 0 <= ci_upper <= 100
    assert ci_lower < ci_upper

    # CI should capture the true fail rate of 40%
    # With n=50, we expect CI to be roughly [25%, 55%] for 40% fail rate
    assert ci_lower < 40  # Lower bound below observed rate
    assert ci_upper > 40  # Upper bound above observed rate
    assert ci_upper - ci_lower < 40  # CI width should be reasonable for n=50
