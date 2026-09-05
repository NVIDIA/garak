# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for red_team.conversation.prune.

`process_output_on_topic_score` returns None for an unjudged prompt, but TAP
feeds that score straight into `prune` as a `sorting_score`. `prune` sorts on it
and filters it with `> 0`, neither of which accepts None -- which is why
`tap_main.run_tap` coerces None to 1.0 at the call site before pruning. These
tests pin that contract so the coercion is not dropped later.
"""

import numpy as np
import pytest

from garak.exception import GarakException
from garak.resources.red_team.conversation import prune

ATTACK_PARAMS = {"width": 3}


def _lists(n):
    """Positional list arguments prune() prunes alongside the scores."""
    return {
        "adv_prompt_list": [f"prompt{i}" for i in range(n)],
        "improv_list": [f"improv{i}" for i in range(n)],
        "convs_list": [f"conv{i}" for i in range(n)],
        "extracted_attack_list": [{"prompt": f"prompt{i}"} for i in range(n)],
    }


def test_prune_rejects_none_sorting_score():
    """A None score reaches prune() only if a caller forgot to coerce it.

    This is the failure the tap_main.run_tap coercion exists to prevent: it
    surfaces as a TypeError out of the sort, aborting the run mid-scan.
    """
    scores = [1.0, None, 0.0, 1.0]
    with pytest.raises(TypeError):
        prune(
            scores,
            None,  # judge_scores
            **_lists(4),
            target_response_list=None,
            sorting_score=scores,
            attack_params=ATTACK_PARAMS,
        )


def test_prune_accepts_coerced_scores():
    """The coercion tap_main applies leaves prune() a usable sorting score."""
    raw_scores = [1.0, None, 0.0, 1.0]
    # mirrors garak/resources/tap/tap_main.py
    scores = [1.0 if score is None else score for score in raw_scores]

    on_topic_scores, _, adv_prompt_list, _, _, _, _ = prune(
        scores,
        None,  # judge_scores
        **_lists(4),
        target_response_list=None,
        sorting_score=scores,
        attack_params=ATTACK_PARAMS,
    )

    assert len(adv_prompt_list) == len(on_topic_scores)
    assert all(score is not None for score in on_topic_scores)


def test_prune_keeps_unjudged_branch():
    """An unjudged branch coerced to 1.0 survives pruning, as it did before.

    Pruning is a search-budget decision rather than a safety verdict, so the
    branch is kept. The other scores are chosen so `width` worth of branches
    already clear the `> 0` filter: that keeps get_first_k's "fewer than two
    survivors" fallback out of the way, so this fails if the coercion is
    dropped or changed to 0.0. Seeded because prune() shuffles equal scores.
    """
    np.random.seed(0)
    raw_scores = [None, 1.0, 1.0, 0.0]
    scores = [1.0 if score is None else score for score in raw_scores]

    _, _, adv_prompt_list, _, _, _, _ = prune(
        scores,
        None,  # judge_scores
        **_lists(4),
        target_response_list=None,
        sorting_score=scores,
        attack_params=ATTACK_PARAMS,
    )

    assert (
        "prompt0" in adv_prompt_list
    ), "the branch we could not judge must not be silently pruned away"


def test_prune_drops_zero_scored_branches():
    """Scores of 0 are pruned -- the behaviour the `> 0` filter provides."""
    np.random.seed(0)
    scores = [1.0, 1.0, 0.0, 0.0]

    _, _, adv_prompt_list, _, _, _, _ = prune(
        scores,
        None,  # judge_scores
        **_lists(4),
        target_response_list=None,
        sorting_score=scores,
        attack_params=ATTACK_PARAMS,
    )

    assert set(adv_prompt_list) == {"prompt0", "prompt1"}


def test_prune_truncates_to_width():
    """Surviving branches are capped at attack_params['width']."""
    np.random.seed(0)
    scores = [1.0] * 5

    _, _, adv_prompt_list, _, _, _, _ = prune(
        scores,
        None,  # judge_scores
        **_lists(5),
        target_response_list=None,
        sorting_score=scores,
        attack_params=ATTACK_PARAMS,
    )

    assert len(adv_prompt_list) == ATTACK_PARAMS["width"]


def test_prune_requires_two_elements():
    """prune() is only called with more than one branch; it says so loudly."""
    scores = [1.0]
    with pytest.raises(GarakException):
        prune(
            scores,
            None,  # judge_scores
            **_lists(1),
            target_response_list=None,
            sorting_score=scores,
            attack_params=ATTACK_PARAMS,
        )
