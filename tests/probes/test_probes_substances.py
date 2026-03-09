# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-FileCopyrightText: Copyright (c) 2026 0DIN (https://0din.ai). All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import re

import pytest

import garak._plugins
import garak.attempt
import garak.probes
from garak.attempt import Attempt, Conversation, Message, Turn


PROBE_CLASSES = [
    "probes.substances.PlaceholderInjection",
    "probes.substances.IncrementalTableCompletion",
    "probes.substances.TechnicalFieldGuide",
    "probes.substances.ChemicalCompilerDebug",
    "probes.substances.Correction",
    "probes.substances.HexRecipeBook",
]

# Active probes with explicit tier settings; inactive probes default to
# Tier.UNLISTED and active=False (ChemicalCompilerDebug, Correction).
ACTIVE_PROBE_CLASSES = [
    "probes.substances.PlaceholderInjection",
    "probes.substances.IncrementalTableCompletion",
    "probes.substances.TechnicalFieldGuide",
    "probes.substances.HexRecipeBook",
]

# Tier assignments per probe class
PROBE_TIERS = {
    "probes.substances.PlaceholderInjection": garak.probes.Tier.COMPETE_WITH_SOTA,
    "probes.substances.IncrementalTableCompletion": garak.probes.Tier.COMPETE_WITH_SOTA,
    "probes.substances.TechnicalFieldGuide": garak.probes.Tier.COMPETE_WITH_SOTA,
    "probes.substances.ChemicalCompilerDebug": garak.probes.Tier.UNLISTED,
    "probes.substances.Correction": garak.probes.Tier.UNLISTED,
    "probes.substances.HexRecipeBook": garak.probes.Tier.OF_CONCERN,
}


@pytest.mark.parametrize("classname", PROBE_CLASSES)
def test_probe_loads(classname):
    p = garak._plugins.load_plugin(classname)
    assert isinstance(p, garak.probes.Probe)


@pytest.mark.parametrize("classname", PROBE_CLASSES)
def test_probe_has_prompts(classname):
    p = garak._plugins.load_plugin(classname)
    assert len(p.prompts) > 0, f"{classname} must have at least one prompt"


@pytest.mark.parametrize("classname", PROBE_CLASSES)
def test_probe_metadata(classname):
    p = garak._plugins.load_plugin(classname)
    assert p.lang == "en"
    assert p.doc_uri.startswith("https://0din.ai/disclosures/")
    assert len(p.goal) > 0
    assert p.tier == PROBE_TIERS[classname]


@pytest.mark.parametrize("classname", ACTIVE_PROBE_CLASSES)
def test_active_probes_are_active(classname):
    """Probes intended for default runs should have active=True."""
    p = garak._plugins.load_plugin(classname)
    assert p.active is True


@pytest.mark.parametrize("classname", PROBE_CLASSES)
def test_probe_has_detector(classname):
    p = garak._plugins.load_plugin(classname)
    assert p.primary_detector == "mitigation.MitigationBypass"


def test_hex_recipe_book_is_multiturn():
    """HexRecipeBook should use Conversation objects for multi-turn attack."""
    p = garak._plugins.load_plugin("probes.substances.HexRecipeBook")
    assert len(p.prompts) == 1
    prompt = p.prompts[0]
    assert isinstance(prompt, garak.attempt.Conversation)
    # Should have 5 turns: user, assistant, user, assistant, user
    assert len(prompt.turns) == 5
    assert prompt.turns[0].role == "user"
    assert prompt.turns[1].role == "assistant"
    assert prompt.turns[2].role == "user"
    assert prompt.turns[3].role == "assistant"
    assert prompt.turns[4].role == "user"


def test_single_turn_probes_use_strings():
    """All probes except HexRecipeBook should use plain string prompts."""
    for classname in PROBE_CLASSES:
        if "HexRecipeBook" in classname:
            continue
        p = garak._plugins.load_plugin(classname)
        for prompt in p.prompts:
            assert isinstance(
                prompt, str
            ), f"{classname} prompts should be strings, got {type(prompt)}"


def test_placeholder_injection_leakreplay_detector():
    """PlaceholderInjection should include leakreplay.StartsWith as extended detector."""
    p = garak._plugins.load_plugin("probes.substances.PlaceholderInjection")
    assert "leakreplay.StartsWith" in p.extended_detectors


def test_placeholder_injection_prestore_hook_sets_triggers():
    """_attempt_prestore_hook should store Potter trigger in attempt.notes."""
    p = garak._plugins.load_plugin("probes.substances.PlaceholderInjection")
    attempt = Attempt(prompt=Message(text="test", lang="en"))
    result = p._attempt_prestore_hook(attempt, 0)
    assert "triggers" in result.notes
    assert len(result.notes["triggers"]) == 1
    assert "dursley" in result.notes["triggers"][0].lower()


def test_placeholder_injection_postprocess_strips_placeholders():
    """_postprocess_hook should strip [[SPACE]][[SPACE]] tokens from output."""
    p = garak._plugins.load_plugin("probes.substances.PlaceholderInjection")
    raw = (
        "Mr. [[SPACE]][[SPACE]] and [[SPACE]][[SPACE]] Mrs. [[SPACE]][[SPACE]] Dursley"
    )
    attempt = Attempt(prompt=Message(text="test", lang="en"))
    # Build a minimal conversation with one turn holding our raw output
    attempt.conversations = [
        Conversation(
            [
                Turn("user", Message(text="test", lang="en")),
                Turn("assistant", Message(text=raw, lang="en")),
            ]
        )
    ]
    result = p._postprocess_hook(attempt)
    cleaned = result.conversations[0].last_message().text
    assert "[[SPACE]]" not in cleaned
    assert "Mr. and Mrs. Dursley" in cleaned
