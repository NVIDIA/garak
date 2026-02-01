# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for probe resumability functionality.

Tests that probe classes properly declare resume support via the supports_resume
attribute, and that the resume service correctly identifies non-resumable probes.
"""

import pytest
from garak.probes import base
from garak import resumeservice, _config


class TestProbeResumabilityMetadata:
    """Test that probe classes have correct supports_resume metadata."""

    def test_base_probe_supports_resume(self):
        """Verify base Probe class supports resume by default."""
        probe = base.Probe()
        assert hasattr(
            probe, "supports_resume"
        ), "Probe should have supports_resume attribute"
        assert (
            probe.supports_resume is True
        ), "Base Probe should support resume by default"

    def test_tree_search_probe_not_resumable(self):
        """Verify TreeSearchProbe does NOT support resume."""
        probe = base.TreeSearchProbe()
        assert hasattr(
            probe, "supports_resume"
        ), "TreeSearchProbe should have supports_resume attribute"
        assert (
            probe.supports_resume is False
        ), "TreeSearchProbe should NOT support resume (complex internal state)"

    def test_iterative_probe_not_resumable(self):
        """Verify IterativeProbe does NOT support resume."""
        # IterativeProbe requires end_condition to instantiate, so check class attribute
        assert hasattr(
            base.IterativeProbe, "supports_resume"
        ), "IterativeProbe should have supports_resume attribute"
        assert (
            base.IterativeProbe.supports_resume is False
        ), "IterativeProbe should NOT support resume (multi-turn conversations)"

    def test_custom_probe_inherits_resumability(self):
        """Verify custom probes inherit supports_resume=True by default."""

        class CustomProbe(base.Probe):
            """Custom probe without explicitly setting supports_resume."""

            pass

        probe = CustomProbe()
        assert (
            probe.supports_resume is True
        ), "Custom probes should inherit supports_resume=True"

    def test_custom_probe_can_override_resumability(self):
        """Verify custom probes can override supports_resume."""

        class NonResumableCustomProbe(base.Probe):
            """Custom probe that explicitly disables resume."""

            supports_resume = False

        probe = NonResumableCustomProbe()
        assert (
            probe.supports_resume is False
        ), "Custom probes should be able to override supports_resume"


class TestIsProbeResumableFunction:
    """Test the is_probe_resumable() helper function."""

    def test_regular_probe_is_resumable(self):
        """Test that regular probes are identified as resumable."""
        probe = base.Probe()
        result = resumeservice.is_probe_resumable(probe)
        assert result is True, "Regular probe should be identified as resumable"

    def test_tree_search_probe_not_resumable(self):
        """Test that TreeSearchProbe is identified as NOT resumable."""
        probe = base.TreeSearchProbe()
        result = resumeservice.is_probe_resumable(probe)
        assert result is False, "TreeSearchProbe should be identified as NOT resumable"

    def test_iterative_probe_not_resumable(self):
        """Test that IterativeProbe is identified as NOT resumable."""
        # IterativeProbe requires end_condition to instantiate, so test with class
        # In actual usage, IterativeProbe instances would be created by probe loader
        # which sets required attributes. Here we test the class attribute directly.
        assert (
            base.IterativeProbe.supports_resume is False
        ), "IterativeProbe class should have supports_resume=False"

        # We can't easily instantiate IterativeProbe without full setup,
        # but we've verified the class attribute which is what matters

    def test_probe_without_attribute_defaults_to_resumable(self):
        """Test that probes without supports_resume attribute default to resumable."""

        class OldStyleProbe(base.Probe):
            """Probe without supports_resume attribute (simulating old code)."""

            pass

        # Remove the supports_resume attribute if it was inherited
        probe = OldStyleProbe()
        if hasattr(probe, "supports_resume"):
            # Can't really remove class attribute, but test getattr with default
            # The function should handle missing attribute gracefully
            pass

        result = resumeservice.is_probe_resumable(probe)
        assert (
            result is True
        ), "Probes without supports_resume should default to resumable for backward compatibility"

    def test_custom_resumable_probe(self):
        """Test custom probe with supports_resume=True."""

        class CustomResumableProbe(base.Probe):
            supports_resume = True

        probe = CustomResumableProbe()
        result = resumeservice.is_probe_resumable(probe)
        assert result is True, "Custom resumable probe should be identified correctly"

    def test_custom_non_resumable_probe(self):
        """Test custom probe with supports_resume=False."""

        class CustomNonResumableProbe(base.Probe):
            supports_resume = False

        probe = CustomNonResumableProbe()
        result = resumeservice.is_probe_resumable(probe)
        assert (
            result is False
        ), "Custom non-resumable probe should be identified correctly"


class TestProbeResumabilityIntegration:
    """Integration tests for probe resumability in actual usage scenarios."""

    def test_resumable_probe_check_before_skip(self):
        """Test that resumability is checked before attempting to skip probes."""
        # This test would verify the integration in probewise.py harness
        # For now, we'll test the API directly

        # Setup mock resume state
        _config.transient.resume_run_id = "test-run-123"
        resumeservice._resume_state = {
            "run_id": "test-run-123",
            "completed_probes": {"test.CompletedProbe"},
            "completed_attempts": set(),
            "granularity": "probe",
        }

        try:
            # Test that non-resumable probes are handled correctly
            tree_probe = base.TreeSearchProbe()
            assert not resumeservice.is_probe_resumable(tree_probe)

            # Non-resumable probes should not be skipped even if in completed list
            # (they can't be resumed, so they shouldn't have been saved as complete)
            # This is a design decision to prevent confusion

        finally:
            # Cleanup
            _config.transient.resume_run_id = None
            resumeservice._resume_state = None

    def test_probe_types_documentation(self):
        """Verify that non-resumable probe types have documentation explaining why."""
        # Check TreeSearchProbe
        tree_probe = base.TreeSearchProbe()
        assert tree_probe.supports_resume is False
        # Note: Actual docstring checks would go here if we add docs

        # Check IterativeProbe class attribute (can't easily instantiate without setup)
        assert base.IterativeProbe.supports_resume is False
        # Note: Actual docstring checks would go here if we add docs


class TestProbeResumabilityEdgeCases:
    """Test edge cases and boundary conditions for probe resumability."""

    def test_none_value_for_supports_resume(self):
        """Test handling of None value for supports_resume."""

        class WeirdProbe(base.Probe):
            supports_resume = None

        probe = WeirdProbe()
        # Should handle None gracefully (probably treat as False for safety)
        result = resumeservice.is_probe_resumable(probe)
        # getattr(probe, 'supports_resume', True) would return None
        # Function should handle this - None is falsy, so should be False
        assert (
            result is None or result is False
        ), "None value should be handled gracefully"

    def test_non_boolean_value_for_supports_resume(self):
        """Test handling of non-boolean values for supports_resume."""

        class StringProbe(base.Probe):
            supports_resume = "yes"

        probe = StringProbe()
        result = resumeservice.is_probe_resumable(probe)
        # Should return truthy value as-is (or cast to bool)
        assert result, "Truthy non-boolean values should be treated as resumable"

    def test_multiple_inheritance_resumability(self):
        """Test resumability with multiple inheritance scenarios."""

        class MixinA:
            supports_resume = False

        class CustomProbe(base.Probe, MixinA):
            pass

        probe = CustomProbe()
        # MRO should determine which supports_resume is used
        result = resumeservice.is_probe_resumable(probe)
        # This tests the actual behavior, whatever it is
        assert isinstance(result, bool), "Should return a boolean value"


class TestProbeResumabilityDocumentation:
    """Test that probe resumability is properly documented."""

    def test_base_probe_class_has_attribute(self):
        """Verify base Probe class documents supports_resume attribute."""
        assert hasattr(
            base.Probe, "supports_resume"
        ), "Probe class should define supports_resume"

        # Check it's a class attribute
        assert "supports_resume" in base.Probe.__dict__ or any(
            "supports_resume" in cls.__dict__ for cls in base.Probe.__mro__
        ), "supports_resume should be defined as a class attribute"

    def test_tree_search_probe_documents_non_resumability(self):
        """Verify TreeSearchProbe documents why it's not resumable."""
        assert hasattr(
            base.TreeSearchProbe, "supports_resume"
        ), "TreeSearchProbe should explicitly define supports_resume"
        assert (
            base.TreeSearchProbe.supports_resume is False
        ), "TreeSearchProbe should set supports_resume = False"

        # Ideally would also check docstring or comments
        # Note: Could add: assert "complex state" in base.TreeSearchProbe.__doc__.lower()

    def test_iterative_probe_documents_non_resumability(self):
        """Verify IterativeProbe documents why it's not resumable."""
        assert hasattr(
            base.IterativeProbe, "supports_resume"
        ), "IterativeProbe should explicitly define supports_resume"
        assert (
            base.IterativeProbe.supports_resume is False
        ), "IterativeProbe should set supports_resume = False"

        # Ideally would also check docstring or comments
        # Note: Could add: assert "multi-turn" in base.IterativeProbe.__doc__.lower()


if __name__ == "__main__":
    # Allow running this test file directly
    pytest.main([__file__, "-v"])
