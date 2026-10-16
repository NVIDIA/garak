# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.resources.red_team.conversation import prune


ATTACK_PARAMS = {"width": 3}


def _make_args(n, on_topic_scores, judge_scores=None):
    prompts = [f"prompt_{i}" for i in range(n)]
    improvs = [f"improv_{i}" for i in range(n)]
    convs = [{"id": i} for i in range(n)]
    attacks = [{"prompt": p, "improvement": imp} for p, imp in zip(prompts, improvs)]
    targets = [f"resp_{i}" for i in range(n)] if judge_scores is not None else None
    return prompts, improvs, convs, attacks, targets


def test_prune_phase1_none_scores_do_not_crash():
    """prune() must not raise TypeError when phase-1 sorting_score contains None."""
    n = 4
    on_topic = [1.0, None, 0.0, None]
    prompts, improvs, convs, attacks, _ = _make_args(n, on_topic)

    result = prune(
        on_topic,
        None,
        prompts,
        improvs,
        convs,
        None,
        attacks,
        sorting_score=on_topic,
        attack_params=ATTACK_PARAMS,
    )
    assert result is not None


def test_prune_phase2_none_scores_do_not_crash():
    """prune() must not raise TypeError when phase-2 sorting_score contains None."""
    n = 4
    on_topic = [1.0, 1.0, 1.0, 1.0]
    judge = [8.0, None, 5.0, None]
    prompts, improvs, convs, attacks, targets = _make_args(n, on_topic, judge)

    result = prune(
        on_topic,
        judge,
        prompts,
        improvs,
        convs,
        targets,
        attacks,
        sorting_score=judge,
        attack_params=ATTACK_PARAMS,
    )
    assert result is not None


def test_prune_all_none_sorting_scores_returns_minimum_two():
    """When all sorting scores are None, prune falls back to the minimum 2-item safety list."""
    n = 4
    all_none = [None, None, None, None]
    prompts, improvs, convs, attacks, _ = _make_args(n, all_none)

    _, _, pruned_prompts, *_ = prune(
        all_none,
        None,
        prompts,
        improvs,
        convs,
        None,
        attacks,
        sorting_score=all_none,
        attack_params=ATTACK_PARAMS,
    )
    assert len(pruned_prompts) >= 2
