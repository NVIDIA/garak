# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.probes.base
from garak import _config

ADAPTIVE_PROBES = ("probes.adaptive_attacks.AdaptiveAttacks",)


@pytest.mark.parametrize("probename", ADAPTIVE_PROBES)
def test_adaptive_attacks_load(probename):
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", ADAPTIVE_PROBES)
def test_adaptive_attacks_has_prompts(probename):
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) > 0, "Probe must have at least one prompt"


@pytest.mark.parametrize("probename", ADAPTIVE_PROBES)
def test_adaptive_attacks_prompts_contain_template_markers(probename):
    p = garak._plugins.load_plugin(probename)
    sample = p.prompts[0]
    # Adaptive template contract: directive role, structured response scaffold,
    # and the no-"I" affirmative-opener constraint must all survive into the
    # rendered prompt.
    assert "Step 1:" in sample
    assert "Never start your response with" in sample
    assert "educational and research purposes" in sample


def test_adaptive_attacks_respects_soft_probe_prompt_cap():
    cap = 5
    original_cap = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = cap
    try:
        from garak.probes.adaptive_attacks import AdaptiveAttacks

        probe = AdaptiveAttacks()
        assert (
            len(probe.prompts) <= cap
        ), f"AdaptiveAttacks has {len(probe.prompts)} prompts, expected at most {cap}"
    finally:
        _config.run.soft_probe_prompt_cap = original_cap
