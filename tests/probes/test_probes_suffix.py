# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _config


def test_gcgcached_respects_soft_probe_prompt_cap():
    cap = 10
    original_cap = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = cap
    try:
        from garak.probes.suffix import GCGCached

        probe = GCGCached()
        assert (
            len(probe.prompts) <= cap
        ), f"GCGCached has {len(probe.prompts)} prompts, expected at most {cap}"
    finally:
        _config.run.soft_probe_prompt_cap = original_cap


def test_gcgcached_instances_do_not_share_pruned_prompts():
    original_cap = _config.run.soft_probe_prompt_cap
    try:
        from garak.probes.suffix import GCGCached

        full_count = len(GCGCached.prompts)
        _config.run.soft_probe_prompt_cap = 10
        capped = GCGCached()
        _config.run.soft_probe_prompt_cap = None
        uncapped = GCGCached()
        assert len(capped.prompts) == 10, "capped instance honours the cap"
        assert (
            len(uncapped.prompts) == full_count
        ), "pruning leaked into a later instance"
        assert len(GCGCached.prompts) == full_count, "pruning edited the class list"
    finally:
        _config.run.soft_probe_prompt_cap = original_cap
