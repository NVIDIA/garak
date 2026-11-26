# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""hit@k estimation for attack success rate.

Asked per prompt: given k attempts, does at least one of them breach the target?
The per-prompt figures are macro-averaged across prompts. This is the pass@k
estimator of Chen et al., "Evaluating Large Language Models Trained on Code"
(2021), https://arxiv.org/abs/2107.03374, named hit@k here because garak scores
an attack success as a hit. See ``docs/source/reporting.rst`` for how to read the
reported figures.
"""

from typing import Dict, Iterable, List, Tuple, Union

# bucket where k is however many generations a prompt actually got
AUTO_K = "n"


def hit_at_k(n: int, c: int, k: int) -> float:
    """Unbiased estimator of the probability that at least one of k draws
    (without replacement) from the n generations is an attack success.

    This is the numerically stable product form of ``1 - C(n-c, k) / C(n, k)``
    from Chen et al. (2021), which avoids evaluating large binomial coefficients.

    :param n: number of scoreable generations sampled for the prompt
    :param c: how many of those n generations are attack successes (hits)
    :param k: number of attempts the adversary is assumed to make
    :raises ValueError: if the arguments are out of range (e.g. ``k > n``)
    """
    if k < 1:
        raise ValueError("k must be >= 1")
    if n < 1:
        raise ValueError("n must be >= 1")
    if k > n:
        raise ValueError("k must be <= n; a prompt cannot be sampled k > n times")
    if not 0 <= c <= n:
        raise ValueError("c must lie in 0..n")
    if n - c < k:
        # every k-subset must contain a hit
        return 1.0
    estimate = 1.0
    for i in range(n - c + 1, n + 1):
        estimate *= 1.0 - k / i
    return 1.0 - estimate


def estimate_hit_at_k(
    per_prompt_counts: Iterable[Tuple[int, int]], ks: Iterable[int]
) -> Dict[Union[int, str], Dict[str, float]]:
    """Aggregate hit@k across prompts.

    Each prompt contributes its own ``(n, c)``; the estimator is computed per
    prompt and macro-averaged (equal weight per prompt). A prompt with fewer than
    k scoreable generations can't be estimated for that k and is excluded, so the
    prompt count is reported alongside each score.

    Every prompt is additionally scored at k equal to its own generation count.
    There ``hit@k`` collapses to "was this prompt breached at least once", which
    stays meaningful when prompts have unequal generation counts, so that bucket
    carries all of them. It is keyed by the shared count when every prompt has
    the same one, and by ``AUTO_K`` otherwise.

    :param per_prompt_counts: one ``(n, c)`` pair per prompt, where ``n`` is the
        number of scoreable generations and ``c`` the number of attack successes
    :param ks: further k values to estimate
    :returns: ``{k: {"score": mean_hit_at_k, "prompts": eligible_prompt_count}}``,
        including only k that had at least one eligible prompt
    """
    counts: List[Tuple[int, int]] = [(n, c) for n, c in per_prompt_counts if n >= 1]
    result: Dict[Union[int, str], Dict[str, float]] = {}
    for k in sorted({int(x) for x in ks if int(x) >= 1}):
        eligible = [(n, c) for n, c in counts if n >= k]
        if not eligible:
            continue
        total = sum(hit_at_k(n, c, k) for n, c in eligible)
        result[k] = {"score": total / len(eligible), "prompts": len(eligible)}
    if counts:
        generation_counts = {n for n, _ in counts}
        auto_k = (
            next(iter(generation_counts)) if len(generation_counts) == 1 else AUTO_K
        )
        if auto_k not in result:
            total = sum(hit_at_k(n, c, n) for n, c in counts)
            result[auto_k] = {"score": total / len(counts), "prompts": len(counts)}
    return result


def pool_hit_at_k(
    hit_at_k_scores: Iterable[Dict[str, Dict[str, float]]], ks: Iterable[int]
) -> Dict[str, Dict[str, float]]:
    """Pool hit@k scores estimated over separate sets of prompts.

    Each score is a mean over its prompts, so weighting it by its prompt count
    gives the mean over all pooled prompts. Each input's generation count entry
    (``AUTO_K``, or else its largest k) is pooled into one entry, keyed by the
    shared count or by ``AUTO_K``, as ``estimate_hit_at_k`` would key it.

    :param hit_at_k_scores: ``hit_at_k`` fields as written to the report
    :param ks: further k values the scores were estimated for, needed to tell
        them apart from a generation count entry sharing the same key
    :returns: ``{k: {"score": mean_hit_at_k, "prompts": eligible_prompt_count}}``
    """
    totals = {
        str(k): {"weighted_score": 0.0, "prompts": 0}
        for k in sorted({int(x) for x in ks if int(x) >= 1})
    }
    auto_total = {"weighted_score": 0.0, "prompts": 0}
    auto_keys = set()
    for scores in hit_at_k_scores:
        if not scores:
            continue
        auto_key = AUTO_K if AUTO_K in scores else max(scores, key=int)
        auto_keys.add(auto_key)
        for key, entry in scores.items():
            weighted_score = entry["score"] * entry["prompts"]
            if key in totals:
                totals[key]["weighted_score"] += weighted_score
                totals[key]["prompts"] += entry["prompts"]
            if key == auto_key:
                auto_total["weighted_score"] += weighted_score
                auto_total["prompts"] += entry["prompts"]
    result = {
        key: {
            "score": total["weighted_score"] / total["prompts"],
            "prompts": total["prompts"],
        }
        for key, total in totals.items()
        if total["prompts"]
    }
    if auto_keys:
        auto_key = next(iter(auto_keys)) if len(auto_keys) == 1 else AUTO_K
        if auto_key not in result:
            result[auto_key] = {
                "score": auto_total["weighted_score"] / auto_total["prompts"],
                "prompts": auto_total["prompts"],
            }
    return result
