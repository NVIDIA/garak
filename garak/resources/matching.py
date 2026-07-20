# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


def ngram_contained_match(
    target: str, context: str, n: int = 4, case_sensitive: bool = False
) -> float:
    """Return the proportion of target's character n-grams found in text (0.0–1.0).

    This is an asymmetric containment metric: it measures how much of
    *target* appears anywhere in *text*, regardless of extra content in
    *text*.
    """
    if context is None or target is None:
        return 0.0

    if len(target) < n:
        return 0.0

    if not case_sensitive:
        target = target.lower()
        context = context.lower()

    target_ngrams = set(target[i : i + n] for i in range(len(target) - (n - 1)))
    matching_ngrams = sum(int(ngram in context) for ngram in target_ngrams)

    return matching_ngrams / len(target_ngrams)
