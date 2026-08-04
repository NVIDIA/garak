# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for donotanswer probe JSONL data files and probe loading.

Each category has a .jsonl file in garak/data/donotanswer/ containing prompts
and per-prompt intent annotations.

Generic checks (loading, isinstance, non-empty prompts) are covered by
tests/plugins/test_plugin_load.py.  These tests focus on what is unique to
the DoNotAnswer module: class generation from DNA_PROBE_TAGS, the local
JSONL data-loading path (including per-prompt intents), per-category
tag / goal / detector correctness, and the active/tier flags.
"""

import json

import pytest

import garak._plugins
import garak.probes.base
import garak.probes.donotanswer as dna
from garak import _plugins
from garak.data import path as data_path
from garak.probes._tier import Tier

DNA_CATEGORIES = [
    "discrimination_exclusion_toxicity_hateful_offensive",
    "human_chatbox",
    "information_hazard",
    "malicious_uses",
    "misinformation_harms",
]

# Mapping: dna_category -> expected class name
CATEGORY_TO_CLASS = {
    "discrimination_exclusion_toxicity_hateful_offensive": "DiscriminationExclusionToxicityHatefulOffensive",
    "human_chatbox": "HumanChatbox",
    "information_hazard": "InformationHazard",
    "malicious_uses": "MaliciousUses",
    "misinformation_harms": "MisinformationHarms",
}

ALL_CLASS_NAMES = list(CATEGORY_TO_CLASS.values())


# ---------------------------------------------------------------------------
# 1. Module-level class generation
# ---------------------------------------------------------------------------


def test_all_expected_classes_are_generated():
    """DNA_PROBE_TAGS keys must each produce a class in the module."""
    for classname in ALL_CLASS_NAMES:
        assert hasattr(
            dna, classname
        ), f"Expected class '{classname}' to be generated in donotanswer module"


def test_generated_classes_are_probe_subclasses():
    """Every generated class must be a subclass of garak.probes.base.Probe."""
    for classname in ALL_CLASS_NAMES:
        cls = getattr(dna, classname)
        assert issubclass(
            cls, garak.probes.base.Probe
        ), f"{classname} must be a subclass of Probe"


def test_class_names_match_titlecase_of_category():
    """Class names must be the title-cased, underscore-stripped category string."""
    for category, expected_classname in CATEGORY_TO_CLASS.items():
        derived = category.title().replace("_", "")
        assert (
            derived == expected_classname
        ), f"Derived classname '{derived}' != expected '{expected_classname}'"


# ---------------------------------------------------------------------------
# 2. dna_category attribute
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("category, classname", list(CATEGORY_TO_CLASS.items()))
def test_dna_category_attribute(category, classname):
    """Each probe must carry dna_category matching its source dict key."""
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert p.dna_category == category


# ---------------------------------------------------------------------------
# 3. Goal string derivation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("category, classname", list(CATEGORY_TO_CLASS.items()))
def test_goal_derived_from_category(category, classname):
    """Goal must be 'get model to respond as <category with spaces>'."""
    expected_goal = f"get model to respond as {category.replace('_', ' ')}"
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert p.goal == expected_goal


# ---------------------------------------------------------------------------
# 4. Primary detector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("classname", ALL_CLASS_NAMES)
def test_primary_detector_is_mitigation_bypass(classname):
    """All DNA probes must use mitigation.MitigationBypass as primary detector."""
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert p.primary_detector == "mitigation.MitigationBypass"


# ---------------------------------------------------------------------------
# 5. Tags correctness
# ---------------------------------------------------------------------------


def test_information_hazard_tags_include_owasp():
    p = garak._plugins.load_plugin("probes.donotanswer.InformationHazard")
    assert "owasp:llm06" in p.tags


def test_misinformation_harms_tags_include_owasp():
    p = garak._plugins.load_plugin("probes.donotanswer.MisinformationHarms")
    assert "owasp:llm09" in p.tags


def test_human_chatbox_tags_include_security():
    p = garak._plugins.load_plugin("probes.donotanswer.HumanChatbox")
    assert "avid-effect:security:S0301" in p.tags


def test_discrimination_tags_include_toxicity():
    p = garak._plugins.load_plugin(
        "probes.donotanswer.DiscriminationExclusionToxicityHatefulOffensive"
    )
    assert "quality:Behavioral:ContentSafety:Toxicity" in p.tags


def test_malicious_uses_tags_include_legal():
    p = garak._plugins.load_plugin("probes.donotanswer.MaliciousUses")
    assert "quality:Behavioral:ContentSafety:LegalGoodsServices" in p.tags


# ---------------------------------------------------------------------------
# 6. active flag and tier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("classname", ALL_CLASS_NAMES)
def test_probes_are_inactive(classname):
    """DNA probes must have active=False (strong content norms caveat)."""
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert p.active is False


@pytest.mark.parametrize("classname", ALL_CLASS_NAMES)
def test_probes_tier_is_unlisted(classname):
    """DNA probes must be Tier.UNLISTED."""
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert p.tier == Tier.UNLISTED


# ---------------------------------------------------------------------------
# 7. URI attribute
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("classname", ALL_CLASS_NAMES)
def test_uri_points_to_arxiv_paper(classname):
    """URI must reference the Do-Not-Answer arXiv paper."""
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert "arxiv.org" in p.uri
    assert "2308.13387" in p.uri


# ---------------------------------------------------------------------------
# 8. Language
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("classname", ALL_CLASS_NAMES)
def test_lang_is_english(classname):
    p = garak._plugins.load_plugin(f"probes.donotanswer.{classname}")
    assert p.lang == "en"


# ---------------------------------------------------------------------------
# 9. JSONL data file form and content, prompt/intent loading
# ---------------------------------------------------------------------------


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
