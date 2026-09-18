# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for AgentHealthBench probes."""

import pytest

import garak._plugins
import garak.probes.base

AGENT_HEALTH_PROBES = [
    "probes.agent_health_atomic.ToolMisuse",
    "probes.agent_health_atomic.ActionChain",
    "probes.agent_health_comm.IdentitySpoof",
    "probes.agent_health_emergent.CascadeFailure",
    "probes.agent_health_immunity.VaccineRecall",
]

REQUIRED_ATTRS = [
    "lang",
    "active",
    "tags",
    "goal",
    "primary_detector",
    "prompts",
]


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_probe_loads(probename):
    """Each AgentHealthBench probe must load as a garak Probe."""
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_probe_has_required_attrs(probename):
    """Each probe must define lang, active, tags, goal, primary_detector, prompts."""
    p = garak._plugins.load_plugin(probename)
    for attr in REQUIRED_ATTRS:
        assert hasattr(p, attr), f"{probename} missing attribute '{attr}'"


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_probe_prompt_count(probename):
    """Each probe must have at least 30 prompts."""
    p = garak._plugins.load_plugin(probename)
    assert (
        len(p.prompts) >= 30
    ), f"{probename} has only {len(p.prompts)} prompts, need >= 30"


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_probe_lang_is_en(probename):
    """All AgentHealthBench probes use English."""
    p = garak._plugins.load_plugin(probename)
    assert p.lang == "en", f"{probename} lang should be 'en', got '{p.lang}'"


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_probe_active(probename):
    """All probes should be active."""
    p = garak._plugins.load_plugin(probename)
    assert p.active is True, f"{probename} should be active"


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_probe_primary_detector_points_to_agent_health(probename):
    """primary_detector should reference agent_health detector."""
    p = garak._plugins.load_plugin(probename)
    assert p.primary_detector is not None
    assert (
        "agent_health" in p.primary_detector
    ), f"{probename} primary_detector should reference agent_health"


@pytest.mark.parametrize("probename", AGENT_HEALTH_PROBES)
def test_prompts_are_strings(probename):
    """All prompts must be non-empty strings."""
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) > 0
    for i, prompt in enumerate(p.prompts):
        assert isinstance(prompt, str), f"prompt[{i}] in {probename} is not a string"
        assert len(prompt.strip()) > 0, f"prompt[{i}] in {probename} is empty"
