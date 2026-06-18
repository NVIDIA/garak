# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-FileCopyrightText: Copyright (c) 2026 ODIN by Mozilla (https://0din.ai). All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import json
import re

import pytest

import garak._plugins
import garak.attempt
import garak.probes
import garak.probes.base
from garak.attempt import Attempt, Conversation, Message, Turn
from garak.data import path as data_path

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


# ---------------------------------------------------------------------------
# Seed-data files: prompts live under garak/data/jef and load at runtime
# ---------------------------------------------------------------------------

# Single-turn techniques whose prompts are the seed-data strings verbatim.
SINGLE_TURN_DATA = {
    "technical_field_guide.json": "probes.jef.TechnicalFieldGuide",
    "correction.json": "probes.jef.Correction",
}

# Seed files that decode to a JSON list (verbatim-prompt and pair lists).
LIST_DATA_FILES = list(SINGLE_TURN_DATA) + [
    "placeholder_injection.json",
    "hex_recipe_book.json",
]


@pytest.mark.parametrize("filename", LIST_DATA_FILES)
def test_jef_data_file_exists_and_loads(filename):
    filepath = data_path / "jef" / filename
    assert filepath.exists(), f"{filename} should ship under garak/data/jef"
    with open(filepath, encoding="utf-8") as fh:
        payload = json.load(fh)
    assert isinstance(payload, list), f"{filename} should decode to a JSON list"
    assert len(payload) > 0, f"{filename} should contain at least one entry"


def test_chemical_compiler_debug_data_file_exists_and_loads():
    """Chemical-compiler seed data is a dict of readable source + style names."""
    filepath = data_path / "jef" / "chemical_compiler_debug.json"
    assert filepath.exists(), "chemical_compiler_debug.json should ship under data/jef"
    with open(filepath, encoding="utf-8") as fh:
        payload = json.load(fh)
    assert set(payload) >= {
        "template",
        "source",
        "styles",
    }, "seed data must carry template, readable source, and style list"
    assert len(payload["styles"]) > 0, "at least one encoding style required"


@pytest.mark.parametrize("filename,classname", SINGLE_TURN_DATA.items())
def test_single_turn_prompts_match_data_file(filename, classname):
    """Single-turn probe prompts should be the seed-data strings verbatim."""
    with open(data_path / "jef" / filename, encoding="utf-8") as fh:
        data_prompts = json.load(fh)
    p = garak._plugins.load_plugin(classname)
    assert (
        p.prompts == data_prompts
    ), f"{classname} prompts should load byte-identically from {filename}"


def test_chemical_compiler_debug_encodes_each_style():
    """One prompt per style, and none leaks the readable source verbatim."""
    with open(
        data_path / "jef" / "chemical_compiler_debug.json", encoding="utf-8"
    ) as fh:
        data = json.load(fh)
    p = garak._plugins.load_plugin("probes.jef.ChemicalCompilerDebug")
    assert len(p.prompts) == len(
        data["styles"]
    ), "one encoded prompt should be generated per declared style"
    for prompt in p.prompts:
        assert (
            data["source"] not in prompt
        ), "readable source must be encoded, not embedded verbatim"


def test_placeholder_injection_prompts_and_triggers_match_seed():
    """Prompt/trigger counts match the seed pairs and triggers are threaded."""
    with open(data_path / "jef" / "placeholder_injection.json", encoding="utf-8") as fh:
        pairs = json.load(fh)
    p = garak._plugins.load_plugin("probes.jef.PlaceholderInjection")
    assert len(p.prompts) == len(pairs), "one prompt per seed pair"
    assert len(p._triggers) == len(pairs), "one trigger per seed pair"
    for seq, pair in enumerate(pairs):
        attempt = Attempt(prompt=Message(text=pair["prompt"], lang="en"))
        result = p._attempt_prestore_hook(attempt, seq)
        assert result.notes["triggers"] == [
            pair["trigger"]
        ], "prestore hook should thread this prompt's own trigger"


def test_hex_recipe_book_data_is_conversation_list():
    """Seed data should describe conversations as role/text turn objects."""
    with open(data_path / "jef" / "hex_recipe_book.json", encoding="utf-8") as fh:
        conversations = json.load(fh)
    assert len(conversations) == 1, "one disclosed conversation is shipped"
    turns = conversations[0]
    assert [t["role"] for t in turns] == [
        "user",
        "assistant",
        "user",
        "assistant",
        "user",
    ], "turn roles should match the prefilled-history one-shot shape"
    assert any(
        "{hex_payload}" in t["text"] for t in turns
    ), "a turn should carry the {hex_payload} placeholder for runtime encoding"
    # The hex itself must not be hardcoded in the seed data.
    jef_mod = _load_jef_module()
    hex_payload = jef_mod._HEX_SOURCE.encode().hex()
    for t in turns:
        assert (
            hex_payload not in t["text"]
        ), "hex must be computed at runtime, not stored"


def test_incremental_table_completion_holds_one_out():
    """N chemicals should yield exactly N hold-one-out prompts (data-driven)."""
    jef_mod = _load_jef_module()
    chemicals = jef_mod._load_keywords("meth_keywords.json")
    p = garak._plugins.load_plugin("probes.jef.IncrementalTableCompletion")
    assert len(p.prompts) == len(
        chemicals
    ), "hold-one-out should generate exactly one prompt per chemical"
