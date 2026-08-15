# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Wilson score interval for binomial proportions.

The non-parametric bootstrap used by ``bootstrap_ci`` degenerates when every
observed outcome is identical (a 0% or 100% rate): every resample is identical,
so the percentile interval has zero width. A zero-width interval is not a
narrow interval — it is degenerate, and it hides the uncertainty the reader
most needs to see. The Wilson score interval is an honest alternative at the
boundary (e.g. 10/10 → [72%, 100%] at 95%).
"""

import math
from statistics import NormalDist
from typing import Optional, Tuple


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


def fallback_wilson_if_degenerate(
    ci_lower: Optional[float],
    ci_upper: Optional[float],
    successes: int,
    n: int,
    confidence_level: float = 0.95,
) -> Tuple[Optional[float], Optional[float], str]:
    """Return the best CI, falling back to Wilson when bootstrap is degenerate.

    Used by the evaluator: when a bootstrap interval has zero width (all
    resamples identical, i.e. a 0% or 100% observed rate), replace it with a
    Wilson interval so the report shows honest uncertainty instead of nothing.
    Returns ``(lower, upper, method)`` where ``method`` is ``"bootstrap"`` or
    ``"wilson"``.
    """
    if ci_lower is None or ci_upper is None:
        return (None, None, "bootstrap")
    if not math.isclose(ci_lower, ci_upper, abs_tol=1e-9):
        return (ci_lower, ci_upper, "bootstrap")
    wilson = calculate_wilson_ci(successes, n, confidence_level)
    if wilson is None:
        return (ci_lower, ci_upper, "bootstrap")
    return (wilson[0], wilson[1], "wilson")
