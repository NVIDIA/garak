# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for AgentHarm probes (garak.probes.promptinject)."""

from unittest.mock import patch

import pytest

import garak.probes.promptinject as promptinject_module
from garak import _plugins
from garak.probes.promptinject import CATEGORIES

# ---------------------------------------------------------------------------
# Minimal mock dataset — one base row + one augmented row per category so
# that both hint_included and detailed_prompt axes are covered.
# ---------------------------------------------------------------------------

_MOCK_ROWS = []
for _i, _cat in enumerate(CATEGORIES):
    _MOCK_ROWS.append(
        {
            "id": f"{_cat.lower()}_base",
            "id_original": f"orig_{_i}_0",
            "category": _cat,
            "prompt": f"Do a {_cat.lower()} harmful task (base)",
            "hint_included": False,
            "detailed_prompt": False,
            "name": f"task_{_i}",
            "target_functions": [],
            "grading_function": "",
        }
    )
    _MOCK_ROWS.append(
        {
            "id": f"{_cat.lower()}_aug",
            "id_original": f"orig_{_i}_1",
            "category": _cat,
            "prompt": f"Do a {_cat.lower()} harmful task (augmented)",
            "hint_included": True,
            "detailed_prompt": True,
            "name": f"task_{_i}_aug",
            "target_functions": [],
            "grading_function": "",
        }
    )


@pytest.fixture(autouse=True)
def mock_hf_dataset():
    """Patch datasets.load_dataset so no real network call is made."""
    with patch(
        "datasets.load_dataset",
        return_value=list(_MOCK_ROWS),
    ) as mock_load:
        yield mock_load


# ---------------------------------------------------------------------------
# AgentHarm (base probe)
# ---------------------------------------------------------------------------


class TestAgentHarmBase:
    def test_instantiates(self):
        p = _plugins.load_plugin("probes.promptinject.AgentHarm")
        assert p is not None

    def test_has_required_attributes(self):
        p = _plugins.load_plugin("probes.promptinject.AgentHarm")
        assert p.lang == "en"
        assert isinstance(p.primary_detector, str)
        assert isinstance(p.tags, list) and len(p.tags) > 0
        assert isinstance(p.goal, str) and len(p.goal) > 0

    def test_prompts_count_equals_categories(self):
        """Base probe loads one row per category (mock has one base row each)."""
        p = _plugins.load_plugin("probes.promptinject.AgentHarm")
        assert len(p.prompts) == len(CATEGORIES)

    def test_no_duplicate_prompts(self):
        p = _plugins.load_plugin("probes.promptinject.AgentHarm")
        assert len(p.prompts) == len(set(p.prompts)), "Duplicate prompts found"

    def test_prompts_are_strings(self):
        p = _plugins.load_plugin("probes.promptinject.AgentHarm")
        for prompt in p.prompts:
            assert isinstance(prompt, str) and len(prompt) > 0

    def test_has_default_params(self):
        """dataset_path, dataset_config, dataset_split must be in DEFAULT_PARAMS."""
        params = promptinject_module.AgentHarm.DEFAULT_PARAMS
        assert "dataset_path" in params
        assert "dataset_config" in params
        assert "dataset_split" in params


# ---------------------------------------------------------------------------
# AgentHarmAugmented
# ---------------------------------------------------------------------------


class TestAgentHarmAugmented:
    def test_instantiates(self):
        p = _plugins.load_plugin("probes.promptinject.AgentHarmAugmented")
        assert p is not None

    def test_more_prompts_than_base(self):
        """Augmented probe loads all rows; should have more than base probe."""
        base = _plugins.load_plugin("probes.promptinject.AgentHarm")
        aug = _plugins.load_plugin("probes.promptinject.AgentHarmAugmented")
        assert len(aug.prompts) > len(base.prompts)

    def test_prompts_count_equals_all_mock_rows(self):
        p = _plugins.load_plugin("probes.promptinject.AgentHarmAugmented")
        assert len(p.prompts) == len(_MOCK_ROWS)


# ---------------------------------------------------------------------------
# Per-category probes
# ---------------------------------------------------------------------------


class TestCategoryProbes:
    @pytest.mark.parametrize("category", CATEGORIES)
    def test_category_probe_instantiates(self, category):
        p = _plugins.load_plugin(f"probes.promptinject.{category}")
        assert p is not None

    @pytest.mark.parametrize("category", CATEGORIES)
    def test_category_probe_prompts_subset_of_base(self, category):
        """Each category probe's prompts must be a subset of the base probe's."""
        base = _plugins.load_plugin("probes.promptinject.AgentHarm")
        cat = _plugins.load_plugin(f"probes.promptinject.{category}")
        for prompt in cat.prompts:
            assert (
                prompt in base.prompts
            ), f"'{prompt}' from {category} probe not in base probe prompts"

    @pytest.mark.parametrize("category", CATEGORIES)
    def test_category_probe_prompts_not_empty(self, category):
        p = _plugins.load_plugin(f"probes.promptinject.{category}")
        assert len(p.prompts) > 0, f"{category} probe returned no prompts"

    def test_category_probes_cover_all_categories(self):
        """Union of all category probes must equal the full base prompt set."""
        base = _plugins.load_plugin("probes.promptinject.AgentHarm")
        all_cat_prompts = set()
        for cat in CATEGORIES:
            p = _plugins.load_plugin(f"probes.promptinject.{cat}")
            all_cat_prompts.update(p.prompts)
        assert all_cat_prompts == set(base.prompts)


# ---------------------------------------------------------------------------
# CrossCategory probe
# ---------------------------------------------------------------------------


class TestCrossCategory:
    def test_instantiates(self):
        p = _plugins.load_plugin("probes.promptinject.CrossCategory")
        assert p is not None

    def test_prompt_count_matches_json(self):
        """CrossCategory should have as many prompts as entries in cross_category.json."""
        entries = promptinject_module._load_cross_category()
        p = _plugins.load_plugin("probes.promptinject.CrossCategory")
        assert len(p.prompts) == len(entries)

    def test_each_entry_has_attack_goal(self):
        """Every entry in cross_category.json must have a non-empty attack_goal."""
        entries = promptinject_module._load_cross_category()
        for entry in entries:
            assert (
                isinstance(entry["attack_goal"], str) and len(entry["attack_goal"]) > 0
            )
            assert (
                entry["category_a"] in CATEGORIES
            ), f"Unknown category: {entry['category_a']}"
            assert (
                entry["category_b"] in CATEGORIES
            ), f"Unknown category: {entry['category_b']}"
            assert entry["category_a"] != entry["category_b"]

    def test_no_duplicate_prompts(self):
        p = _plugins.load_plugin("probes.promptinject.CrossCategory")
        assert len(p.prompts) == len(set(p.prompts))


# ---------------------------------------------------------------------------
# _load_prompts graceful failure
# ---------------------------------------------------------------------------


class TestLoadPromptsGracefulFailure:
    def test_dataset_error_returns_empty(self):
        """When load_dataset raises, _load_prompts returns [] not an exception."""
        with patch(
            "datasets.load_dataset",
            side_effect=Exception("network down"),
        ):
            result = promptinject_module._load_prompts(
                "ai-safety-institute/AgentHarm", "harmful", "test_public"
            )
            assert result == []

    def test_empty_dataset_propagates_to_load_prompts(self):
        """When load_dataset returns empty, _load_prompts also returns []."""
        with patch("datasets.load_dataset", return_value=[]):
            result = promptinject_module._load_prompts(
                "ai-safety-institute/AgentHarm", "harmful", "test_public"
            )
            assert result == []
