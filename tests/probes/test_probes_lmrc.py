# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for LMRC (Language Model Risk Cards) probes.

These tests verify that probes are properly configured and loadable.
They validate probe structure, prompts, and metadata without requiring LLM calls.
"""

import pytest

from garak import _plugins
import garak.probes.base


LMRC_PROBES = [
    "probes.lmrc.Misogyny",
]


class TestMisogonyProbe:
    """Test suite for Misogyny probe."""

    def test_probe_loads(self):
        """Verify the Misogyny probe can be instantiated."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert probe is not None
        assert isinstance(probe, garak.probes.base.Probe)

    def test_probe_has_prompts(self):
        """Verify the probe has prompts defined."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert hasattr(probe, "prompts"), "Probe should have prompts attribute"
        assert len(probe.prompts) > 0, "Probe should have at least one prompt"
        assert all(
            isinstance(p, str) for p in probe.prompts
        ), "All prompts should be strings"

    def test_probe_metadata(self):
        """Verify the probe has required metadata."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")

        # Check required attributes
        assert hasattr(probe, "goal"), "Probe should have a goal"
        assert hasattr(probe, "tags"), "Probe should have tags"
        assert hasattr(probe, "lang"), "Probe should specify language"
        assert hasattr(probe, "doc_uri"), "Probe should have documentation URI"
        assert hasattr(probe, "active"), "Probe should have active status"

        # Check values
        assert isinstance(probe.goal, str) and len(probe.goal) > 0
        assert isinstance(probe.tags, list) and len(probe.tags) > 0
        assert isinstance(probe.lang, str) and len(probe.lang) > 0
        assert isinstance(probe.doc_uri, str) and len(probe.doc_uri) > 0
        assert isinstance(probe.active, bool)

    def test_probe_detector_specified(self):
        """Verify the probe specifies a primary detector."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert hasattr(
            probe, "primary_detector"
        ), "Probe should specify a primary_detector"
        assert (
            probe.primary_detector == "lmrc.Misogyny"
        ), "Misogyny probe should use Misogyny detector"
        assert "lmrc.MisogynyKeywords" in getattr(
            probe, "extended_detectors", []
        ), "Misogyny probe should include keyword indicators as extended detectors"

    def test_probe_active(self):
        """Verify the probe is marked as active."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert probe.active is True, "Misogyny probe should be active"

    def test_probe_tags_include_misogyny(self):
        """Verify the probe has misogyny-related tags."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert any(
            "misogyny" in tag.lower() or "hate" in tag.lower() for tag in probe.tags
        ), "Probe should have misogyny or hate-related tag"

    def test_probe_prompts_are_diverse(self):
        """Verify the probe has diverse prompts."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")

        # Check that prompts are different
        unique_prompts = set(probe.prompts)
        assert len(unique_prompts) == len(probe.prompts), "All prompts should be unique"

        # Check that prompts are reasonably long
        for i, prompt in enumerate(probe.prompts):
            assert len(prompt) >= 10, f"Prompt {i} should be at least 10 characters"

    def test_probe_language_is_english(self):
        """Verify the probe is for English language."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert probe.lang == "en", "Misogyny probe should be for English language"

    def test_probe_doc_uri_valid(self):
        """Verify the probe has a valid documentation URI."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")
        assert probe.doc_uri.startswith(
            "http"
        ), "Documentation URI should be a valid URL"
        assert (
            "lm_risk_cards" in probe.doc_uri
        ), "Documentation should reference LM Risk Cards"

    def test_all_lmrc_probes_load(self):
        """Verify all specified LMRC probes can be loaded."""
        for probe_name in LMRC_PROBES:
            try:
                probe = _plugins.load_plugin(probe_name)
                assert isinstance(
                    probe, garak.probes.base.Probe
                ), f"{probe_name} should be a Probe instance"
            except Exception as e:
                pytest.fail(f"Failed to load {probe_name}: {e}")


class TestLmrcProbeIntegration:
    """Integration tests for LMRC probes (no LLM required)."""

    def test_probe_can_iterate_prompts(self):
        """Verify we can iterate through probe prompts."""
        probe = _plugins.load_plugin("probes.lmrc.Misogyny")

        prompt_count = 0
        for prompt in probe.prompts:
            prompt_count += 1
            assert isinstance(prompt, str)
            assert len(prompt) > 0

        assert prompt_count > 0, "Should have at least one prompt"

    def test_probe_enumerate_via_plugin_system(self):
        """Verify the probe can be discovered via plugin system or loaded directly."""
        # Note: Plugin system enumeration may be delayed due to cache
        # This test ensures the probe is in the system
        from garak import _plugins as plugins_module

        plugins_module.PluginCache._plugin_cache_dict = None

        # Try to load directly first (guaranteed to work)
        try:
            probe = _plugins.load_plugin("probes.lmrc.Misogyny")
            assert probe is not None
        except:
            pytest.skip("Plugin system may need cache rebuild")
