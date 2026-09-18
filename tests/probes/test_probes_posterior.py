# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.probes.base
import garak.probes.posterior

POSTERIOR_PROBES = (
    "probes.posterior.PosteriorAttack",
    "probes.posterior.PosteriorAttackSystemPrompt",
)


@pytest.mark.parametrize("probename", POSTERIOR_PROBES)
def test_posterior_load(probename):
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", POSTERIOR_PROBES)
def test_posterior_detectors(probename):
    p = garak._plugins.load_plugin(probename)
    assert p.primary_detector == "judge.Jailbreak"
    assert "mitigation.Prefixes" in p.extended_detectors
    assert "mitigation.MitigationBypass" not in p.extended_detectors


@pytest.mark.parametrize("probename", POSTERIOR_PROBES)
def test_posterior_prompts_valid(probename):
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) > 0
    assert len(p.prompts) <= len(p.payloads)
    assert len(p.prompts) <= p.soft_probe_prompt_cap

    for prompt in p.prompts:
        assert garak.probes.posterior.BEHAVIOR_MARKER not in prompt
        assert "{generation}" in prompt
        assert 'will make you say "Yes"' in prompt
        assert any(payload in prompt for payload in p.payloads)


def test_posterior_system_prompt():
    base = garak._plugins.load_plugin("probes.posterior.PosteriorAttack")
    sysvariant = garak._plugins.load_plugin(
        "probes.posterior.PosteriorAttackSystemPrompt"
    )
    assert getattr(base, "system_prompt", "") in (None, "")
    assert sysvariant.system_prompt == garak.probes.posterior.AUTODAN_SYSTEM_PROMPT
    assert base.prompts == sysvariant.prompts
