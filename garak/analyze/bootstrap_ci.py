# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional, Tuple

import numpy as np

from garak import _config


def _bootstrap_calculation(
    results: np.ndarray,
    sensitivity: float,
    specificity: float,
    num_iterations: int = None,
    confidence_level: float = None,
) -> Optional[Tuple[float, float]]:
    """Non-parametric bootstrap with Se/Sp correction"""
    if len(results) == 0:
        return None

    if num_iterations is None:
        num_iterations = _config.reporting.bootstrap_num_iterations
    if confidence_level is None:
        confidence_level = _config.reporting.bootstrap_confidence_level

    if (
        hasattr(_config, "run")
        and hasattr(_config.run, "seed")
        and _config.run.seed is not None
    ):
        np.random.seed(_config.run.seed)

    denominator = sensitivity + specificity - 1.0
    if abs(denominator) < 0.01:
        if hasattr(_config.system, "verbose") and _config.system.verbose > 0:
            logging.info(
                "Detector metrics denominator too small (Se+Sp-1=%.4f), falling back to uncorrected CI",
                denominator,
            )
        sensitivity = 1.0
        specificity = 1.0
        denominator = 1.0

    n = len(results)
    corrected_asrs = np.empty(num_iterations)
    
    # No correction needed when denominator ≈ 1.0
    # This occurs when: (1) perfect detector (Se=Sp=1.0), or (2) fallback triggered above (Se+Sp-1 < 0.01)
    is_perfect_detector = np.isclose(denominator, 1.0)
    
    for i in range(num_iterations):
        resampled_results = np.random.choice(results, size=n, replace=True)
        p_obs = resampled_results.mean()
        
        if is_perfect_detector:
            corrected_asrs[i] = p_obs
        else:
            # Apply Se/Sp correction to get bootstrapped ASR
            # TODO: propagate detector metric uncertainty (requires Se/Sp CIs in detector_metrics_summary.json)
            p_true = (p_obs + specificity - 1.0) / denominator
            p_true = np.clip(p_true, 0.0, 1.0)
            corrected_asrs[i] = p_true

    alpha = 1 - confidence_level
    lower_percentile = (alpha / 2) * 100
    upper_percentile = (1 - alpha / 2) * 100

    ci_lower, ci_upper = np.percentile(
        corrected_asrs, [lower_percentile, upper_percentile]
    )

    ci_lower = np.clip(ci_lower * 100, 0.0, 100.0)
    ci_upper = np.clip(ci_upper * 100, 0.0, 100.0)

    if hasattr(_config.system, "verbose") and _config.system.verbose > 0:
        logging.debug(
            "Bootstrap CI calculated: [%.2f, %.2f] with Se=%.3f, Sp=%.3f, n=%d",
            ci_lower,
            ci_upper,
            sensitivity,
            specificity,
            n,
        )

    return (ci_lower, ci_upper)


def calculate_bootstrap_ci(
    results: list,
    sensitivity: float,
    specificity: float,
    num_iterations: int = None,
    confidence_level: float = None,
) -> Optional[Tuple[float, float]]:
    """Calculate non-parametric bootstrap CI for ASR with detector correction"""
    min_sample_size = _config.reporting.bootstrap_min_sample_size
    if len(results) < min_sample_size:
        return None

    results_array = np.array(results, dtype=float)
    return _bootstrap_calculation(
        results_array, sensitivity, specificity, num_iterations, confidence_level
    )
