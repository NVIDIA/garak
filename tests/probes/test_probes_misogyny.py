# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _plugins
from garak.probes.base import Probe
from garak.probes.misogyny import Misogyny


def test_misogyny_is_probe():
    assert issubclass(Misogyny, Probe)


def test_misogyny_tags():
    assert "avid-effect:ethics:E0101" in Misogyny.tags
    assert "avid-effect:ethics:E0301" in Misogyny.tags
    assert "quality:Behavioral:ContentSafety:HateHarassment" in Misogyny.tags
    assert "payload:unwanted:hatespeech" in Misogyny.tags


def test_misogyny_load():
    probe = _plugins.load_plugin("probes.misogyny.Misogyny")
    assert isinstance(probe, Misogyny)
    assert probe.primary_detector == "misogyny.MisogynisticContent"
    assert len(probe.prompts) > 0


def test_misogyny_active():
    assert Misogyny.active is True


def test_misogyny_goal():
    assert Misogyny.goal == "generate misogynistic content"


def test_misogyny_prompts_nonempty_strings():
    probe = _plugins.load_plugin("probes.misogyny.Misogyny")
    for prompt in probe.prompts:
        assert isinstance(prompt, str)
        assert len(prompt.strip()) > 0


def test_misogyny_prompts_have_substance():
    """Per garak's extending.probe.rst, probes should have ~30+ prompts for decent statistics."""
    probe = _plugins.load_plugin("probes.misogyny.Misogyny")
    assert (
        len(probe.prompts) >= 30
    ), f"Probe should have at least 30 prompts for statistical substance, got {len(probe.prompts)}"


def test_misogyny_prompts_are_unique():
    """All prompts should be unique to avoid wasted inference budget."""
    probe = _plugins.load_plugin("probes.misogyny.Misogyny")
    assert len(probe.prompts) == len(set(probe.prompts)), "Duplicate prompts found"


def test_misogyny_prompts_no_duplicates_across_categories():
    """Prompts should not be near-duplicates that waste inference budget."""
    probe = _plugins.load_plugin("probes.misogyny.Misogyny")
    # Check no prompt is a prefix of another (which would indicate redundancy)
    normalized = [p.strip().lower() for p in probe.prompts]
    for i, p1 in enumerate(normalized):
        for j, p2 in enumerate(normalized):
            if i != j and p1 == p2:
                pytest.fail(f"Duplicate prompt: {p1}")
