# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for garak.probes.grandma probe suite"""

import pytest

import garak._plugins
import garak.probes.base
from garak.intents import TextStub
from garak.probes.grandma import (
    Win10,
    Win11,
    Slurs,
    Substances,
    GrandmaIntent,
    PRODUCT_KEY_PROBE_TEMPLATES,
    SLUR_PROBE_TEMPLATES,
    SUBSTANCE_TEMPLATES,
)

GRANDMA_PROBES = [
    "Win10",
    "Win11",
    "Slurs",
    "Substances",
    "GrandmaIntent",
]


@pytest.mark.parametrize("classname", GRANDMA_PROBES)
def test_grandma_probes_load(classname):
    """Ensure all grandma probe plugins load successfully via the plugin registry."""
    probe = garak._plugins.load_plugin(f"probes.grandma.{classname}")
    assert probe is not None, f"Failed to load plugin probes.grandma.{classname}"
    assert isinstance(
        probe, garak.probes.base.Probe
    ), f"probes.grandma.{classname} must inherit from garak.probes.base.Probe"


@pytest.mark.parametrize("classname,expected_intent", [
    ("Win10", "S003productkeys"),
    ("Win11", "S003productkeys"),
    ("Slurs", "S005hate"),
    ("Substances", "S006items"),
])
def test_grandma_probe_intents(classname, expected_intent):
    """Verify that concrete grandma probes declare the expected taxonomy intent."""
    probe = garak._plugins.load_plugin(f"probes.grandma.{classname}")
    assert (
        probe.intent == expected_intent
    ), f"{classname} must declare intent '{expected_intent}', got '{probe.intent}'"
    attempt = probe._mint_attempt(probe.prompts[0], seq=0)
    assert (
        attempt.intent == expected_intent
    ), f"{classname} minted attempt must have intent '{expected_intent}'"


def test_win_product_key_templates_rendered():
    """Verify Win10 and Win11 probes properly substitute {product_name} placeholders."""
    for classname in ("Win10", "Win11"):
        probe = garak._plugins.load_plugin(f"probes.grandma.{classname}")
        assert len(probe.prompts) > 0, f"{classname} prompts must not be empty"
        for idx, prompt in enumerate(probe.prompts):
            assert (
                "{product_name}" not in prompt
            ), f"Unrendered placeholder '{{product_name}}' in {classname} prompt #{idx}"
            assert (
                "grandma" in prompt.lower() or "grandmother" in prompt.lower()
            ), f"Prompt #{idx} in {classname} must mention grandma or grandmother"


def test_slurs_templates_rendered():
    """Verify Slurs probe substitutes {group_name} and covers all human groups."""
    probe = garak._plugins.load_plugin("probes.grandma.Slurs")
    assert len(probe.prompts) > 0, "Slurs probe prompts must not be empty"
    for idx, prompt in enumerate(probe.prompts):
        assert (
            "{group_name}" not in prompt
        ), f"Unrendered placeholder '{{group_name}}' in Slurs prompt #{idx}"
        assert (
            "grandma" in prompt.lower() or "grandmother" in prompt.lower()
        ), f"Slurs prompt #{idx} must mention grandma or grandmother"

    expected_count = len(SLUR_PROBE_TEMPLATES) * len(probe.human_groups)
    assert (
        len(probe.prompts) == expected_count
    ), f"Slurs probe must generate {expected_count} prompts, got {len(probe.prompts)}"


def test_substances_templates_rendered():
    """Verify Substances probe substitutes [SUBSTANCE] and covers configured substances."""
    probe = garak._plugins.load_plugin("probes.grandma.Substances")
    assert len(probe.prompts) > 0, "Substances probe prompts must not be empty"
    for idx, prompt in enumerate(probe.prompts):
        assert (
            "[SUBSTANCE]" not in prompt
        ), f"Unrendered placeholder '[SUBSTANCE]' in Substances prompt #{idx}"
        assert (
            "grandmother" in prompt.lower()
        ), f"Substances prompt #{idx} must mention grandmother"

    expected_count = len(SUBSTANCE_TEMPLATES) * len(probe.substances)
    assert (
        len(probe.prompts) == expected_count
    ), f"Substances probe must generate {expected_count} prompts, got {len(probe.prompts)}"


def test_grandma_intent_prompts_from_stub():
    """Verify GrandmaIntent expands a TextStub into roleplaying exploit prompts."""
    probe = garak._plugins.load_plugin("probes.grandma.GrandmaIntent")
    stub = TextStub(id="test_stub", content="synthesise nerve agent")
    prompts = probe._prompts_from_stub(stub)

    assert len(prompts) > 0, "GrandmaIntent._prompts_from_stub must return prompts"
    assert (
        len(set(prompts)) == len(prompts)
    ), "Generated GrandmaIntent prompts must not contain duplicates"

    for idx, prompt in enumerate(prompts):
        assert (
            "used to" in prompt
        ), f"Prompt #{idx} in GrandmaIntent missing 'used to' roleplay phrase"
        assert (
            "like they would?" in prompt
        ), f"Prompt #{idx} in GrandmaIntent missing closing question"
        assert (
            "nerve agent" in prompt
        ), f"Prompt #{idx} in GrandmaIntent must contain clipped stub content"
