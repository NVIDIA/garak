# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for garak.analyze.hit_at_k — the hit@k ASR estimator and aggregation."""

import math

import pytest

from garak.analyze.hit_at_k import AUTO_K, hit_at_k, estimate_hit_at_k


def _reference(n: int, c: int, k: int) -> float:
    """Direct binomial form of the estimator, for cross-checking."""
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


@pytest.mark.parametrize(
    "n, c, k, expected",
    [
        (5, 1, 1, 0.2),  # single hit in five == one-shot ASR of 20%
        (5, 1, 5, 1.0),  # the lone hit is certain to be among all five draws
        (5, 1, 2, 0.4),  # 1 - C(4,2)/C(5,2)
        (5, 2, 2, 0.7),  # 1 - C(3,2)/C(5,2)
        (5, 0, 3, 0.0),  # no hit can never be drawn
        (4, 4, 1, 1.0),  # every generation is a hit
    ],
)
def test_hit_at_k_known_values(n, c, k, expected):
    assert hit_at_k(n, c, k) == pytest.approx(
        expected
    ), f"hit_at_k({n},{c},{k}) should be {expected}"


@pytest.mark.parametrize("n", range(1, 9))
def test_hit_at_k_matches_binomial_form(n):
    for c in range(n + 1):
        for k in range(1, n + 1):
            assert hit_at_k(n, c, k) == pytest.approx(
                _reference(n, c, k)
            ), f"product form should match C(n-c,k)/C(n,k) for n={n},c={c},k={k}"


@pytest.mark.parametrize("n, c", [(5, 0), (5, 1), (5, 3), (5, 5)])
def test_hit_at_k_at_full_n_is_breached_at_least_once(n, c):
    assert hit_at_k(n, c, n) == (
        1.0 if c else 0.0
    ), "k == n reduces to whether the prompt was ever breached"


def test_hit_at_k_non_decreasing_in_k():
    n, c = 8, 2
    values = [hit_at_k(n, c, k) for k in range(1, n + 1)]
    assert values == sorted(
        values
    ), "hit@k should not decrease as the attacker is given more attempts"


@pytest.mark.parametrize(
    "n, c, k",
    [
        (5, 1, 6),  # k > n
        (5, 1, 0),  # k < 1
        (0, 0, 1),  # n < 1
        (5, 6, 1),  # c > n
        (5, -1, 1),  # c < 0
    ],
)
def test_hit_at_k_rejects_out_of_range(n, c, k):
    with pytest.raises(ValueError):
        hit_at_k(n, c, k)


def test_estimate_macro_averages_the_issue_scenario():
    # five prompts, each breached on 1 reply in 5: pooled ASR reads 20%, but a
    # persistent attacker with five tries breaches every prompt.
    counts = [(5, 1)] * 5
    result = estimate_hit_at_k(counts, [1])
    assert result[1]["score"] == pytest.approx(0.2), "hit@1 recovers per-prompt ASR"
    assert result[5]["score"] == pytest.approx(1.0), "hit@5 exposes guaranteed breach"
    assert result[1]["prompts"] == 5, "all prompts contribute to hit@1"
    assert result[5]["prompts"] == 5, "all prompts contribute to hit@5"


def test_estimate_always_covers_the_generation_count():
    result = estimate_hit_at_k([(4, 1), (4, 0)], [])
    assert list(result) == [4], "the run's own generation count needs no configuration"
    assert result[4]["score"] == pytest.approx(0.5), "one of two prompts ever breached"


def test_estimate_keys_mixed_generation_counts_by_auto_k():
    # a prompt that yielded 3 generations and one that yielded 5 share the bucket
    result = estimate_hit_at_k([(5, 1), (3, 0)], [])
    assert list(result) == [AUTO_K], "no single integer k describes the prompts"
    assert result[AUTO_K]["prompts"] == 2, "every prompt is scored at its own count"
    assert result[AUTO_K]["score"] == pytest.approx(0.5), "one of two prompts breached"


def test_estimate_excludes_prompts_with_too_few_generations():
    # one prompt has only 3 generations, so hit@5 cannot be estimated for it
    result = estimate_hit_at_k([(5, 1), (3, 1)], [5])
    assert result[5]["prompts"] == 1, "prompt with n < k is excluded from hit@k"


def test_estimate_drops_k_with_no_eligible_prompts():
    result = estimate_hit_at_k([(3, 1), (2, 0)], [5])
    assert 5 not in result, "k with no prompt of n >= k should be omitted entirely"


def test_estimate_ignores_empty_and_none_prompts():
    # a prompt whose generations were all unscoreable (n == 0) is skipped
    result = estimate_hit_at_k([(0, 0), (5, 1)], [1])
    assert result[1]["prompts"] == 1, "prompts with no scoreable outputs are ignored"


def test_estimate_orders_k_ascending_with_generation_count_last():
    result = estimate_hit_at_k([(5, 1)], [5, 1, 1])
    assert list(result) == [1, 5], "k values should be unique, sorted and not repeated"


def test_estimate_empty_inputs_return_empty():
    assert estimate_hit_at_k([], [1, 5]) == {}, "no prompts yields no scores"
    assert estimate_hit_at_k([], []) == {}, "no prompts and no k yields no scores"
