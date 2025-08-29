# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.probes.base

DRA_PROBES = (
    "probes.dra.DRA",
    "probes.dra.DRAFull",
    "probes.dra.DRAAdvanced"
)


@pytest.mark.parametrize("probename", DRA_PROBES)
def test_dra_load(probename):
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", DRA_PROBES)
def test_dra_prompts_count(probename):
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) > 0, "Probe must have more than zero prompts"


@pytest.mark.parametrize("probename", DRA_PROBES)
def test_dra_moderation_cache_loaded(probename):
    p = garak._plugins.load_plugin(probename)
    assert hasattr(p, 'moderation_cache'), "DRA probe should have moderation_cache attribute"
    assert isinstance(p.moderation_cache, dict), "Moderation cache should be a dictionary"
    assert len(p.moderation_cache) > 0, "Moderation cache should more than 0 entries"
    
    # Check cached tokens
    sample_token = next(iter(p.moderation_cache.keys()))
    result = p._check_moderation(sample_token)
    assert isinstance(result, bool), "_check_moderation should return a boolean"
