# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""pass@k estimation for attack success rate.

Attack success rate (ASR) pools every generation and reports the fraction that
breach the target. That understates real risk: an adversary doesn't need the
target to fail most of the time, only once, and can keep retrying. A jailbreak
that succeeds on 1 reply in 5 is a working jailbreak, yet pooled ASR records it
as a mild 20%.

pass@k reframes the question per prompt -- "given k attempts, does at least one
succeed?" -- and averages across prompts. It follows Chen et al., "Evaluating
Large Language Models Trained on Code" (2021), https://arxiv.org/abs/2107.03374,
where a "success" here is an attack success: a generation the detector scores as
a hit. pass@1 recovers the familiar per-prompt success rate; larger k exposes
how quickly a persistent attacker's odds climb.
"""

from typing import Dict, Iterable, List, Tuple


def pass_at_k(n: int, c: int, k: int) -> float:
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


def estimate_pass_at_k(
    per_prompt_counts: Iterable[Tuple[int, int]], ks: Iterable[int]
) -> Dict[int, Dict[str, float]]:
    """Aggregate pass@k across prompts.

    Each prompt contributes its own ``(n, c)``; the estimator is computed per
    prompt and macro-averaged (equal weight per prompt). A prompt with fewer than
    k scoreable generations can't be estimated for that k and is excluded, so the
    prompt count is reported alongside each score.

    :param per_prompt_counts: one ``(n, c)`` pair per prompt, where ``n`` is the
        number of scoreable generations and ``c`` the number of attack successes
    :param ks: the k values to estimate
    :returns: ``{k: {"score": mean_pass_at_k, "prompts": eligible_prompt_count}}``,
        including only k that had at least one eligible prompt
    """
    counts: List[Tuple[int, int]] = [(n, c) for n, c in per_prompt_counts if n >= 1]
    result: Dict[int, Dict[str, float]] = {}
    for k in sorted({int(x) for x in ks if int(x) >= 1}):
        eligible = [(n, c) for n, c in counts if n >= k]
        if not eligible:
            continue
        total = sum(pass_at_k(n, c, k) for n, c in eligible)
        result[k] = {"score": total / len(eligible), "prompts": len(eligible)}
    return result
