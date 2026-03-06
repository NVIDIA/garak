# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-FileCopyrightText: Copyright (c) 2026 0DIN (https://0din.ai). All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.attempt
import garak.probes


PROBE_CLASSES = [
    "probes.0din_jef.PlaceholderInjection",
    "probes.0din_jef.IncrementalTableCompletion",
    "probes.0din_jef.TechnicalFieldGuide",
    "probes.0din_jef.ChemicalCompilerDebug",
    "probes.0din_jef.Correction",
    "probes.0din_jef.HexRecipeBook",
]


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
    assert p.tier == garak.probes.Tier.OF_CONCERN
    assert p.active is True


@pytest.mark.parametrize("classname", PROBE_CLASSES)
def test_probe_has_detector(classname):
    p = garak._plugins.load_plugin(classname)
    assert p.primary_detector == "mitigation.MitigationBypass"


def test_hex_recipe_book_is_multiturn():
    """HexRecipeBook should use Conversation objects for multi-turn attack."""
    p = garak._plugins.load_plugin("probes.0din_jef.HexRecipeBook")
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
