# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for donotanswer probe JSONL data files and probe loading.

Each category has a .jsonl file in garak/data/donotanswer/ containing prompts
and per-prompt intent annotations.
"""

import json

import pytest

from garak import _plugins
from garak.data import path as data_path

DNA_CATEGORIES = [
    "discrimination_exclusion_toxicity_hateful_offensive",
    "human_chatbox",
    "information_hazard",
    "malicious_uses",
    "misinformation_harms",
]


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_donotanswer_jsonl_form(category):
    """Each category .jsonl must exist and every line must have a prompt and intents."""
    jsonl_path = data_path / "donotanswer" / f"{category}.jsonl"
    assert jsonl_path.exists(), f"{jsonl_path} must exist"
    with open(jsonl_path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert len(entries) > 0, f"{category}.jsonl must contain at least one entry"
    for i, entry in enumerate(entries):
        assert "prompt" in entry, f"line {i} in {category}.jsonl missing 'prompt'"
        assert "intents" in entry, f"line {i} in {category}.jsonl missing 'intents'"
        assert (
            len(entry["intents"]) >= 1
        ), f"line {i} in {category}.jsonl must have at least one intent"
        assert isinstance(
            entry["intents"][0], str
        ), f"line {i} in {category}.jsonl first intent must be a string"


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_donotanswer_jsonl_content(category, loaded_intent_service):
    """Every intent specifier in the JSONL must pass validation."""
    from garak.services.intentservice import validate_intent_specifier

    jsonl_path = data_path / "donotanswer" / f"{category}.jsonl"
    with open(jsonl_path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    for i, entry in enumerate(entries):
        for intent_code in entry["intents"]:
            assert validate_intent_specifier(
                intent_code
            ), f"line {i} in {category}.jsonl has invalid intent '{intent_code}'"


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_donotanswer_probe_loads_prompts(category, loaded_intent_service):
    """Loading the probe class must populate prompts and matching _prompt_intents."""
    classname = category.title().replace("_", "")
    p = _plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert len(p.prompts) > 0, f"donotanswer.{classname} must load prompts from JSONL"
    assert hasattr(
        p, "_prompt_intents"
    ), f"donotanswer.{classname} must populate _prompt_intents"
    assert len(p._prompt_intents) == len(
        p.prompts
    ), f"_prompt_intents length must match prompts length"


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_donotanswer_attempts(category, loaded_intent_service):
    """Minted attempts at first, middle, and last positions must carry the
    intent declared in the corresponding source JSONL entry."""
    jsonl_path = data_path / "donotanswer" / f"{category}.jsonl"
    with open(jsonl_path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    source_intents = [e["intents"][0] for e in entries]

    classname = category.title().replace("_", "")
    p = _plugins.load_plugin(f"probes.donotanswer.{classname}")

    n = len(p.prompts)
    positions = sorted({0, n // 2, n - 1})
    for idx in positions:
        attempt = p._mint_attempt(p.prompts[idx], seq=idx)
        assert (
            attempt.intent is not None
        ), f"attempt at position {idx} in {category} must have a non-None intent"
        assert isinstance(attempt.intent, str), (
            f"attempt at position {idx} in {category} intent must be a string, "
            f"got {type(attempt.intent).__name__}"
        )
        assert attempt.intent == source_intents[idx], (
            f"attempt at position {idx} in {category} has intent {attempt.intent!r}, "
            f"expected {source_intents[idx]!r} from source JSONL"
        )

    assert (
        len({p._mint_attempt(p.prompts[i], seq=i).intent for i in positions}) > 0
    ), f"at least one sampled attempt in {category} must have a non-empty intent"


# The per-prompt intent contract (issue #1808): donotanswer used to carry a
# bespoke _attempt_prestore_hook to copy its per-entry intents onto attempts.
# The probe base now consumes an aligned self._prompt_intents list, so the
# bespoke hook is gone; these guard that the behaviour it provided survives.


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_dna_prompt_intents_align_with_prompts(category):
    classname = f"probes.donotanswer.{category.title().replace('_', '')}"
    p = _plugins.load_plugin(classname)
    assert len(p._prompt_intents) == len(p.prompts)
    assert all(i for i in p._prompt_intents), "every entry should carry an intent"


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_dna_attempt_carries_its_own_entry_intent(category):
    """Each attempt reports its own entry's intent, without a bespoke hook."""
    classname = f"probes.donotanswer.{category.title().replace('_', '')}"
    p = _plugins.load_plugin(classname)
    assert not hasattr(p, "_dna_attempt_prestore_hook")

    for seq in (0, len(p.prompts) // 2, len(p.prompts) - 1):
        attempt = p._mint_attempt(p.prompts[seq], seq)
        assert attempt.intent == p._prompt_intents[seq]


@pytest.mark.parametrize("category", DNA_CATEGORIES)
def test_dna_attempt_intent_varies_across_entries(category):
    """Guards against every attempt collapsing onto one probe-wide intent."""
    classname = f"probes.donotanswer.{category.title().replace('_', '')}"
    p = _plugins.load_plugin(classname)
    minted = {
        p._mint_attempt(prompt, seq).intent
        for seq, prompt in enumerate(p.prompts)
    }
    assert minted == set(p._prompt_intents)
    assert len(minted) > 1, "these categories span more than one intent"
