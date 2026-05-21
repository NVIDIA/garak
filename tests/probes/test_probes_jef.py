# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-FileCopyrightText: Copyright (c) 2026 ODIN by Mozilla (https://0din.ai). All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import re

import pytest

import garak._plugins
import garak.attempt
import garak.probes
import garak.probes.base
from garak.attempt import Attempt, Conversation, Message, Turn


# ---------------------------------------------------------------------------
# Dynamic probe discovery — avoids hardcoding class names (leondz feedback)
# ---------------------------------------------------------------------------


def _load_jef_module():
    return importlib.import_module("garak.probes.jef")


def _get_probe_classnames():
    """Return list of 'probes.jef.<Name>' for all Probe subclasses in module."""
    mod = _load_jef_module()
    return [
        f"probes.jef.{name}"
        for name, obj in inspect.getmembers(mod, inspect.isclass)
        if issubclass(obj, garak.probes.base.Probe) and obj.__module__ == mod.__name__
    ]


def _get_active_classnames():
    mod = _load_jef_module()
    return [
        f"probes.jef.{name}"
        for name, obj in inspect.getmembers(mod, inspect.isclass)
        if issubclass(obj, garak.probes.base.Probe)
        and obj.__module__ == mod.__name__
        and getattr(obj, "active", False)
    ]


def _get_tier(classname):
    mod = _load_jef_module()
    name = classname.split(".")[-1]
    cls = getattr(mod, name)
    return getattr(cls, "tier", garak.probes.Tier.UNLISTED)


PROBE_CLASSES = _get_probe_classnames()
ACTIVE_PROBE_CLASSES = _get_active_classnames()


# ---------------------------------------------------------------------------
# Basic structural tests
# ---------------------------------------------------------------------------


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
    # tier is set on the class (dynamic check)
    assert isinstance(p.tier, garak.probes.Tier)


@pytest.mark.parametrize("classname", ACTIVE_PROBE_CLASSES)
def test_active_probes_are_active(classname):
    p = garak._plugins.load_plugin(classname)
    assert p.active is True


@pytest.mark.parametrize("classname", PROBE_CLASSES)
def test_probe_has_mitigation_detector(classname):
    p = garak._plugins.load_plugin(classname)
    assert p.primary_detector == "mitigation.MitigationBypass"


# ---------------------------------------------------------------------------
# IncrementalTableCompletion: multiple prompts via hold-one-out
# ---------------------------------------------------------------------------


def test_incremental_table_completion_has_multiple_prompts():
    """Hold-one-out expansion should yield more than one prompt."""
    p = garak._plugins.load_plugin("probes.jef.IncrementalTableCompletion")
    assert len(p.prompts) > 1, (
        "IncrementalTableCompletion should generate multiple prompts "
        "by holding one chemical out at a time"
    )


def test_incremental_table_completion_prompts_are_strings():
    p = garak._plugins.load_plugin("probes.jef.IncrementalTableCompletion")
    for prompt in p.prompts:
        assert isinstance(prompt, str)


# ---------------------------------------------------------------------------
# HexRecipeBook: multi-turn structure + dynamic hex encoding
# ---------------------------------------------------------------------------


def test_hex_recipe_book_is_multiturn():
    p = garak._plugins.load_plugin("probes.jef.HexRecipeBook")
    assert len(p.prompts) == 1
    prompt = p.prompts[0]
    assert isinstance(prompt, garak.attempt.Conversation)
    assert len(prompt.turns) == 5
    assert prompt.turns[0].role == "user"
    assert prompt.turns[1].role == "assistant"
    assert prompt.turns[2].role == "user"
    assert prompt.turns[3].role == "assistant"
    assert prompt.turns[4].role == "user"


def test_hex_recipe_book_turn2_contains_hex():
    """Turn 2 should contain a hex string derived from the source payload."""
    p = garak._plugins.load_plugin("probes.jef.HexRecipeBook")
    turn2_text = p.prompts[0].turns[2].content.text
    # Should contain a long hex string (at least 20 hex chars)
    assert re.search(
        r"[0-9a-f]{20,}", turn2_text
    ), "Turn 2 should contain a hex-encoded payload"


def test_hex_recipe_book_hex_is_dynamic():
    """The hex in turn 2 should decode to the _HEX_SOURCE constant."""
    import garak.probes.jef as jef_mod

    p = garak._plugins.load_plugin("probes.jef.HexRecipeBook")
    turn2_text = p.prompts[0].turns[2].content.text
    # Extract hex token from turn 2
    match = re.search(r"([0-9a-f]{20,})", turn2_text)
    assert match, "No hex found in turn 2"
    decoded = bytes.fromhex(match.group(1)).decode("utf-8")
    assert decoded == jef_mod._HEX_SOURCE


# ---------------------------------------------------------------------------
# PlaceholderInjection: hooks + detector
# ---------------------------------------------------------------------------


def test_single_turn_probes_use_strings():
    for classname in PROBE_CLASSES:
        if "HexRecipeBook" in classname:
            continue
        p = garak._plugins.load_plugin(classname)
        for prompt in p.prompts:
            assert isinstance(
                prompt, str
            ), f"{classname} prompts should be strings, got {type(prompt)}"


def test_placeholder_injection_leakreplay_detector():
    p = garak._plugins.load_plugin("probes.jef.PlaceholderInjection")
    assert "leakreplay.StartsWith" in p.extended_detectors


def test_placeholder_injection_prestore_hook_sets_triggers():
    p = garak._plugins.load_plugin("probes.jef.PlaceholderInjection")
    attempt = Attempt(prompt=Message(text="test", lang="en"))
    result = p._attempt_prestore_hook(attempt, 0)
    assert "triggers" in result.notes
    assert len(result.notes["triggers"]) == 1
    assert "dursley" in result.notes["triggers"][0].lower()


def test_placeholder_injection_postprocess_strips_placeholders():
    p = garak._plugins.load_plugin("probes.jef.PlaceholderInjection")
    raw = (
        "Mr. [[SPACE]][[SPACE]] and [[SPACE]][[SPACE]] Mrs. [[SPACE]][[SPACE]] Dursley"
    )
    attempt = Attempt(prompt=Message(text="test", lang="en"))
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
