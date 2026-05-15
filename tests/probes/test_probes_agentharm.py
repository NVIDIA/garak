# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for garak.probes.agentharm."""

from unittest.mock import patch

import pytest

import garak.probes.agentharm as agentharm_module
from garak import _plugins
from garak.probes.agentharm import CATEGORIES

# Capture the real implementation before the autouse fixture replaces the name.
_real_fetch_all_rows = agentharm_module._fetch_all_rows

# ---------------------------------------------------------------------------
# Minimal mock dataset — one base row + one augmented row per category so
# that both hint_included and detailed_prompt axes are covered.
# ---------------------------------------------------------------------------

_MOCK_ROWS = []
for _i, _cat in enumerate(CATEGORIES):
    # base row: no hint, no detail
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
    # augmented row: hint + detail
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
    """Patch _fetch_all_rows so no real network call is made."""
    with patch(
        "garak.probes.agentharm._fetch_all_rows",
        return_value=list(_MOCK_ROWS),
    ) as mock_fetch:
        yield mock_fetch


# ---------------------------------------------------------------------------
# AgentHarm (base probe)
# ---------------------------------------------------------------------------


class TestAgentHarmBase:
    def test_instantiates(self):
        p = _plugins.load_plugin("probes.agentharm.AgentHarm")
        assert p is not None

    def test_has_required_attributes(self):
        p = _plugins.load_plugin("probes.agentharm.AgentHarm")
        assert p.lang == "en"
        assert isinstance(p.primary_detector, str)
        assert isinstance(p.tags, list) and len(p.tags) > 0
        assert isinstance(p.goal, str) and len(p.goal) > 0

    def test_prompts_count_equals_categories(self):
        """Base probe loads one row per category (mock has one base row each)."""
        p = _plugins.load_plugin("probes.agentharm.AgentHarm")
        assert len(p.prompts) == len(CATEGORIES)

    def test_no_duplicate_prompts(self):
        p = _plugins.load_plugin("probes.agentharm.AgentHarm")
        assert len(p.prompts) == len(set(p.prompts)), "Duplicate prompts found"

    def test_prompts_are_strings(self):
        p = _plugins.load_plugin("probes.agentharm.AgentHarm")
        for prompt in p.prompts:
            assert isinstance(prompt, str) and len(prompt) > 0


# ---------------------------------------------------------------------------
# AgentHarmAugmented
# ---------------------------------------------------------------------------


class TestAgentHarmAugmented:
    def test_instantiates(self):
        p = _plugins.load_plugin("probes.agentharm.AgentHarmAugmented")
        assert p is not None

    def test_more_prompts_than_base(self):
        """Augmented probe loads all rows; should have more than base probe."""
        base = _plugins.load_plugin("probes.agentharm.AgentHarm")
        aug = _plugins.load_plugin("probes.agentharm.AgentHarmAugmented")
        assert len(aug.prompts) > len(base.prompts)

    def test_prompts_count_equals_all_mock_rows(self):
        p = _plugins.load_plugin("probes.agentharm.AgentHarmAugmented")
        assert len(p.prompts) == len(_MOCK_ROWS)


# ---------------------------------------------------------------------------
# Per-category probes
# ---------------------------------------------------------------------------


class TestCategoryProbes:
    @pytest.mark.parametrize("category", CATEGORIES)
    def test_category_probe_instantiates(self, category):
        p = _plugins.load_plugin(f"probes.agentharm.{category}")
        assert p is not None

    @pytest.mark.parametrize("category", CATEGORIES)
    def test_category_probe_prompts_subset_of_base(self, category):
        """Each category probe's prompts must be a subset of the base probe's."""
        base = _plugins.load_plugin("probes.agentharm.AgentHarm")
        cat = _plugins.load_plugin(f"probes.agentharm.{category}")
        for prompt in cat.prompts:
            assert (
                prompt in base.prompts
            ), f"'{prompt}' from {category} probe not in base probe prompts"

    @pytest.mark.parametrize("category", CATEGORIES)
    def test_category_probe_prompts_not_empty(self, category):
        p = _plugins.load_plugin(f"probes.agentharm.{category}")
        assert len(p.prompts) > 0, f"{category} probe returned no prompts"

    def test_category_probes_cover_all_categories(self):
        """Union of all category probes must equal the full base prompt set."""
        base = _plugins.load_plugin("probes.agentharm.AgentHarm")
        all_cat_prompts = set()
        for cat in CATEGORIES:
            p = _plugins.load_plugin(f"probes.agentharm.{cat}")
            all_cat_prompts.update(p.prompts)
        assert all_cat_prompts == set(base.prompts)


# ---------------------------------------------------------------------------
# CrossCategory probe
# ---------------------------------------------------------------------------


class TestCrossCategory:
    def test_instantiates(self):
        p = _plugins.load_plugin("probes.agentharm.CrossCategory")
        assert p is not None

    def test_prompt_count_equals_curated_pairs(self):
        """CrossCategory should have exactly as many prompts as curated pairs."""
        from garak.probes.agentharm import _CROSS_CATEGORY_PROMPTS

        p = _plugins.load_plugin("probes.agentharm.CrossCategory")
        assert len(p.prompts) == len(_CROSS_CATEGORY_PROMPTS)

    def test_each_prompt_has_attack_goal(self):
        """Every curated pair must have a non-empty attack_goal."""
        from garak.probes.agentharm import _CROSS_CATEGORY_PROMPTS

        for cat_a, cat_b, prompt, goal in _CROSS_CATEGORY_PROMPTS:
            assert isinstance(goal, str) and len(goal) > 0
            assert cat_a in CATEGORIES, f"Unknown category: {cat_a}"
            assert cat_b in CATEGORIES, f"Unknown category: {cat_b}"
            assert cat_a != cat_b, f"Same category in pair: {cat_a}"

    def test_no_duplicate_prompts(self):
        p = _plugins.load_plugin("probes.agentharm.CrossCategory")
        assert len(p.prompts) == len(set(p.prompts))


# ---------------------------------------------------------------------------
# _load_prompts graceful failure
# ---------------------------------------------------------------------------


class TestLoadPromptsGracefulFailure:
    def test_network_error_makes_fetch_return_empty(self):
        """When urllib raises (network down), _fetch_all_rows returns [] not an exception."""
        import urllib.request

        # Call the real function (captured before autouse replaced the name) so
        # the try/except inside it is exercised rather than the autouse mock.
        with patch.object(
            urllib.request, "urlopen", side_effect=OSError("unreachable")
        ):
            result = _real_fetch_all_rows()
            assert result == []

    def test_empty_fetch_propagates_to_load_prompts(self):
        """When _fetch_all_rows returns [], _load_prompts also returns []."""
        with patch("garak.probes.agentharm._fetch_all_rows", return_value=[]):
            result = agentharm_module._load_prompts()
            assert result == []
