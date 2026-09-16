# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Wilson score interval for binomial proportions.

The non-parametric bootstrap used by ``bootstrap_ci`` degenerates when every
resample yields the same corrected rate: every resample is identical, so the
percentile interval has zero width. A zero-width interval is not a narrow
interval — it is degenerate, and it hides the uncertainty the reader most
needs to see. The Wilson score interval is an honest alternative at the
boundary (e.g. 10/10 → [72%, 100%] at 95%).

Degeneracy is not limited to a 0% or 100% observed rate: with a weak detector,
the Se/Sp correction clips a whole range of observed rates to the same bound,
and any of them produces a zero-width bootstrap interval. Bounds returned on
the fallback path (and by the explicit Wilson method) are mapped through
``apply_detector_correction`` so they report on the same corrected-ASR scale
as the bootstrap rows next to them. When that correction itself collapses the
bounds onto one clipped edge, the raw-scale Wilson interval is returned under
``"wilson_uncorrected"`` instead of a zero-width cell. Se/Sp are treated as
exactly known: the correction shifts the interval but does not widen it for
detector-metric uncertainty.
"""

import math
from statistics import NormalDist
from typing import Optional, Tuple

from garak.analyze.bootstrap_ci import apply_detector_correction


def _z_score(confidence_level: float) -> float:
    """Two-sided standard-normal quantile for ``confidence_level``."""
    return NormalDist().inv_cdf((1.0 + confidence_level) / 2.0)


def calculate_wilson_ci(
    successes: int,
    n: int,
    confidence_level: float = 0.95,
) -> Optional[Tuple[float, float]]:
    """Return the Wilson score interval for ``successes`` out of ``n``, in percent.

    Returns ``None`` for invalid inputs (non-positive ``n`` or a count outside
    ``[0, n]``). The interval is clamped to ``[0, 100]``.
    """
    if n <= 0 or successes < 0 or successes > n:
        return None
    if not 0.0 < confidence_level < 1.0:
        return None

    z = _z_score(confidence_level)
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2.0 * n)) / denom
    margin = z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n) / denom
    return (
        max(0.0, (centre - margin) * 100.0),
        min(100.0, (centre + margin) * 100.0),
    )


def apply_correction_or_raw(
    wilson: Tuple[float, float],
    sensitivity: float = 1.0,
    specificity: float = 1.0,
) -> Tuple[float, float, str]:
    """Map Wilson bounds onto the corrected scale, or keep the raw scale.

    Returns ``(lower, upper, method)`` with ``method`` ``"wilson"`` when the
    corrected interval has nonzero width, else the uncorrected Wilson bounds
    with ``"wilson_uncorrected"`` so the caller never emits a zero-width cell
    that display logic would suppress (#2033).
    """
    corrected_lower, corrected_upper = apply_detector_correction(
        wilson, sensitivity, specificity
    )
    if math.isclose(corrected_lower, corrected_upper, abs_tol=1e-9):
        return (wilson[0], wilson[1], "wilson_uncorrected")
    return (corrected_lower, corrected_upper, "wilson")


def fallback_wilson_if_degenerate(
    ci_lower: Optional[float],
    ci_upper: Optional[float],
    successes: int,
    n: int,
    confidence_level: float = 0.95,
    sensitivity: float = 1.0,
    specificity: float = 1.0,
) -> Tuple[Optional[float], Optional[float], str]:
    """Return the best CI, falling back to Wilson when bootstrap is degenerate.

    Used by the evaluator: when a bootstrap interval has zero width (all
    resamples identical — a 0%/100% observed rate, or observed rates that the
    Se/Sp correction clips to the same bound), replace it with a Wilson
    interval so the report shows honest uncertainty instead of nothing. The
    Wilson bounds are mapped onto the Se/Sp-corrected ASR scale via
    ``sensitivity``/``specificity`` so they measure the same quantity as the
    bootstrap rows they sit beside; the defaults (1.0, 1.0) keep the raw
    bounds for a perfect detector. When the correction collapses the Wilson
    bounds onto one clipped edge, the raw-scale Wilson interval is returned
    as ``"wilson_uncorrected"`` rather than a zero-width ``"wilson"`` cell.
    Returns ``(lower, upper, method)`` where ``method`` is ``"bootstrap"``,
    ``"wilson"``, or ``"wilson_uncorrected"``.
    """
    if ci_lower is None or ci_upper is None:
        return (None, None, "bootstrap")
    if not math.isclose(ci_lower, ci_upper, abs_tol=1e-9):
        return (ci_lower, ci_upper, "bootstrap")
    wilson = calculate_wilson_ci(successes, n, confidence_level)
    if wilson is None:
        return (ci_lower, ci_upper, "bootstrap")
    return apply_correction_or_raw(wilson, sensitivity, specificity)
