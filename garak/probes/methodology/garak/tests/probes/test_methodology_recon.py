"""Tests for ReconProbe."""

import pytest
from garak.probes.methodology.recon import ReconProbe, HypothesisTest, ReconFinding


class TestReconProbeInitialization:
    """Test ReconProbe initialization and configuration."""

    def test_probe_creation(self):
        """Test that ReconProbe can be instantiated."""
        probe = ReconProbe()
        assert probe is not None
        assert hasattr(probe, "scope_config")
        assert hasattr(probe, "hypotheses")
        assert hasattr(probe, "findings")

    def test_scope_config_exists(self):
        """Test that scope configuration is initialized."""
        probe = ReconProbe()
        assert isinstance(probe.scope_config, dict)
        assert "target_model" in probe.scope_config
        assert "api_endpoint" in probe.scope_config

    def test_scope_config_modification(self):
        """Test that scope config can be modified."""
        probe = ReconProbe()
        probe.scope_config["target_model"] = "test-model"
        assert probe.scope_config["target_model"] == "test-model"


class TestPhaseExecution:
    """Test execution of six-phase methodology."""

    def test_prestore_hook_execution(self):
        """Test Phase 1-3: Scope Lock, Recon, Setup."""
        probe = ReconProbe()
        probe._attempt_prestore_hook()
        assert len(probe.hypotheses) > 0
        assert len(probe.model_capabilities) > 0

    def test_hypothesis_loading(self):
        """Test that hypotheses are loaded with expected structure."""
        probe = ReconProbe()
        probe._attempt_prestore_hook()
        for hypothesis in probe.hypotheses:
            assert isinstance(hypothesis, HypothesisTest)
            assert hypothesis.name
            assert hypothesis.payload

    def test_attempt_execution(self):
        """Test Phase 4: Manual Testing - execute an attempt."""
        probe = ReconProbe()
        probe._attempt_prestore_hook()
        attempt = probe._execute_attempt("Test prompt payload")
        assert attempt is not None
        assert attempt.prompt == "Test prompt payload"
        assert "vulnerable" in attempt.metrics


class TestFindingExport:
    """Test Phase 5: Documentation - finding export."""

    def test_export_empty_findings_json(self):
        """Test JSON export with no findings."""
        probe = ReconProbe()
        json_output = probe.export_findings(format="json")
        assert isinstance(json_output, str)
        assert "[]" in json_output

    def test_export_empty_findings_markdown(self):
        """Test Markdown export with no findings."""
        probe = ReconProbe()
        md_output = probe.export_findings(format="markdown")
        assert isinstance(md_output, str)
        assert "# ReconProbe Findings" in md_output


class TestProbeMetadata:
    """Test garak Probe metadata."""

    def test_probe_has_required_attributes(self):
        """Test that probe has required garak Probe attributes."""
        probe = ReconProbe()
        assert hasattr(probe, "bcp47")
        assert hasattr(probe, "doc_uri")
        assert hasattr(probe, "tags")
        assert hasattr(probe, "goal")

    def test_probe_bcp47_is_en(self):
        """Test that probe specifies English language."""
        probe = ReconProbe()
        assert probe.bcp47 == "en"
