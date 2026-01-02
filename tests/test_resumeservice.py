"""Tests for the resume service."""

import pytest
from unittest.mock import patch, MagicMock

from garak import _config, resumeservice


@pytest.fixture(autouse=True)
def reset_resume_state():
    """Reset resume service state before and after each test."""
    resumeservice.reset()
    yield
    resumeservice.reset()
    _config.transient.resume_file = None


@pytest.fixture
def set_seed_42():
    """Set seed to 42 to match test resource files."""
    if not hasattr(_config, "run"):
        _config.run = MagicMock()
    _config.run.seed = 42
    yield


class TestResumeServiceEnabled:
    """Tests for the enabled() function."""

    def test_enabled_when_resume_file_set(self):
        """Test that enabled() returns True when resume_file is set."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"
        assert resumeservice.enabled() is True

    def test_disabled_when_resume_file_none(self):
        """Test that enabled() returns False when resume_file is None."""
        _config.transient.resume_file = None
        assert resumeservice.enabled() is False


class TestResumeServiceStartMsg:
    """Tests for the start_msg() function."""

    def test_start_msg_when_enabled(self):
        """Test that start_msg() returns appropriate message when enabled."""
        _config.transient.resume_file = "/path/to/resume.report.jsonl"
        emoji, msg = resumeservice.start_msg()
        assert emoji == "🔄"
        assert "resuming scan from" in msg
        assert "/path/to/resume.report.jsonl" in msg

    def test_start_msg_when_disabled(self):
        """Test that start_msg() returns empty strings when disabled."""
        _config.transient.resume_file = None
        emoji, msg = resumeservice.start_msg()
        assert emoji == ""
        assert msg == ""


class TestResumeServiceLoad:
    """Tests for the load() function."""

    def test_load_completed_report(self, set_seed_42):
        """Test loading a report with completed attempts."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"
        resumeservice.load()

        completed = resumeservice.get_completed_attempts()
        assert "probes.test.TestProbe" in completed
        assert completed["probes.test.TestProbe"] == {0, 1}
        assert "probes.other.OtherProbe" in completed
        assert completed["probes.other.OtherProbe"] == {0}

    def test_load_pending_report(self, set_seed_42):
        """Test loading a report with pending detection attempts."""
        _config.transient.resume_file = "tests/_assets/resume_test_pending.report.jsonl"
        resumeservice.load()

        pending = resumeservice.get_pending_detection_attempts()
        assert "probes.test.TestProbe" in pending
        assert 0 in pending["probes.test.TestProbe"]

        # Verify full data is stored
        stored_data = pending["probes.test.TestProbe"][0]
        assert stored_data["uuid"] == "44444444-4444-4444-4444-444444444444"
        assert stored_data["goal"] == "pending goal"
        assert stored_data["targets"] == ["target1"]

    def test_load_mixed_report(self, set_seed_42):
        """Test loading a report with mixed status attempts."""
        _config.transient.resume_file = "tests/_assets/resume_test_mixed.report.jsonl"
        resumeservice.load()

        completed = resumeservice.get_completed_attempts()
        pending = resumeservice.get_pending_detection_attempts()

        # Only seq=2 should be completed (status=2)
        assert completed["probes.test.TestProbe"] == {2}

        # seq=1 (status=1) should be in pending_detection
        assert "probes.test.TestProbe" in pending
        assert 1 in pending["probes.test.TestProbe"]

    def test_load_file_not_found(self):
        """Test that FileNotFoundError is raised for missing file."""
        _config.transient.resume_file = "/nonexistent/path/to/file.jsonl"

        with pytest.raises(FileNotFoundError) as exc_info:
            resumeservice.load()

        assert "Resume file not found" in str(exc_info.value)

    def test_load_extracts_metadata(self, set_seed_42):
        """Test that metadata is extracted from checkpoint."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"
        resumeservice.load()

        metadata = resumeservice.get_metadata()
        assert metadata["garak_version"] == "0.13.4.pre1"
        assert metadata["seed"] == 42
        assert metadata["probe_spec"] == "probes.test.TestProbe"

    def test_load_only_loads_once(self, set_seed_42):
        """Test that load() only parses the file once."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        # First load
        resumeservice.load()
        completed_first = resumeservice.get_completed_attempts()

        # Second load should return same data without re-parsing
        resumeservice.load()
        completed_second = resumeservice.get_completed_attempts()

        assert completed_first == completed_second


class TestResumeServicePublicAPI:
    """Tests for public API functions."""

    def test_get_completed_seqs_exact_match(self, set_seed_42):
        """Test get_completed_seqs with exact probe name match."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        seqs = resumeservice.get_completed_seqs("probes.test.TestProbe")
        assert seqs == {0, 1}

    def test_get_completed_seqs_short_name(self, set_seed_42):
        """Test get_completed_seqs with short probe name."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        # The file stores short names, so looking up with full name should still work
        seqs = resumeservice.get_completed_seqs("garak.probes.test.TestProbe")
        # This should find the short name
        assert seqs == {0, 1}

    def test_get_completed_seqs_not_found(self, set_seed_42):
        """Test get_completed_seqs returns empty set for unknown probe."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        seqs = resumeservice.get_completed_seqs("nonexistent.Probe")
        assert seqs == set()

    def test_get_pending_attempts(self, set_seed_42):
        """Test get_pending_attempts retrieves correct data."""
        _config.transient.resume_file = "tests/_assets/resume_test_pending.report.jsonl"

        pending = resumeservice.get_pending_attempts("probes.test.TestProbe")
        assert 0 in pending
        assert pending[0]["status"] == 1

    def test_is_attempt_completed_true(self, set_seed_42):
        """Test is_attempt_completed returns True for completed attempt."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        assert resumeservice.is_attempt_completed("probes.test.TestProbe", 0) is True
        assert resumeservice.is_attempt_completed("probes.test.TestProbe", 1) is True

    def test_is_attempt_completed_false(self, set_seed_42):
        """Test is_attempt_completed returns False for non-completed attempt."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        assert resumeservice.is_attempt_completed("probes.test.TestProbe", 99) is False

    def test_get_pending_attempt_data(self, set_seed_42):
        """Test get_pending_attempt_data retrieves specific attempt data."""
        _config.transient.resume_file = "tests/_assets/resume_test_pending.report.jsonl"

        data = resumeservice.get_pending_attempt_data("probes.test.TestProbe", 0)
        assert data is not None
        assert data["uuid"] == "44444444-4444-4444-4444-444444444444"

    def test_get_pending_attempt_data_not_found(self, set_seed_42):
        """Test get_pending_attempt_data returns None for missing attempt."""
        _config.transient.resume_file = "tests/_assets/resume_test_pending.report.jsonl"

        data = resumeservice.get_pending_attempt_data("probes.test.TestProbe", 99)
        assert data is None

    def test_returns_empty_when_not_enabled(self):
        """Test that API functions return empty values when not enabled."""
        _config.transient.resume_file = None

        assert resumeservice.get_completed_attempts() == {}
        assert resumeservice.get_pending_detection_attempts() == {}
        assert resumeservice.get_completed_seqs("any.Probe") == set()
        assert resumeservice.get_pending_attempts("any.Probe") == {}
        assert resumeservice.get_metadata() == {}


class TestResumeServiceValidation:
    """Tests for checkpoint validation."""

    def test_version_mismatch_raises_error(self):
        """Test that version mismatch raises ResumeValidationError."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        # Set seed to match but version to mismatch
        if not hasattr(_config, "run"):
            _config.run = MagicMock()
        _config.run.seed = 42

        # The checkpoint has version 0.13.4.pre1, mock a different version
        with patch.object(_config, "version", "0.99.0"):
            with pytest.raises(resumeservice.ResumeValidationError) as exc_info:
                resumeservice.load()

        assert "version mismatch" in str(exc_info.value).lower()

    def test_resume_works_without_seed(self):
        """Test that resume works when checkpoint has no seed (prompt-based matching)."""
        import tempfile
        import json

        # Create temp file WITHOUT seed in metadata
        with tempfile.NamedTemporaryFile(mode="w", suffix=".report.jsonl", delete=False) as f:
            f.write(json.dumps({"entry_type": "init", "garak_version": _config.version}) + "\n")
            # No run.seed in setup entry
            f.write(json.dumps({"entry_type": "start_run setup", "plugins.probe_spec": "test.Probe"}) + "\n")
            f.write(json.dumps({
                "entry_type": "attempt",
                "status": 2,
                "probe_classname": "test.Probe",
                "seq": 0,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "probe_params": {},
                "targets": [],
                "prompt": {"turns": [{"role": "user", "content": {"text": "test"}}]},
                "outputs": [{"text": "response"}],
                "detector_results": {},
                "notes": {},
                "goal": "test",
                "conversations": []
            }) + "\n")
            temp_path = f.name

        try:
            _config.transient.resume_file = temp_path

            # Should NOT raise error - seed validation removed
            resumeservice.load()

            # Verify data was loaded
            completed = resumeservice.get_completed_attempts()
            assert "test.Probe" in completed
        finally:
            import os
            os.unlink(temp_path)

    def test_resume_works_with_different_seed(self):
        """Test that resume works even with different seed (prompt-based matching)."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        # Set different seed than checkpoint (checkpoint has seed=42)
        if not hasattr(_config, "run"):
            _config.run = MagicMock()
        _config.run.seed = 999

        # Should NOT raise error - seed validation removed
        resumeservice.load()

        # Verify data was loaded
        completed = resumeservice.get_completed_attempts()
        assert "probes.test.TestProbe" in completed


class TestPromptBasedMatching:
    """Tests for prompt-based matching functionality."""

    def test_hash_prompt_consistency(self, set_seed_42):
        """Test that same prompt produces same hash."""
        prompt_dict = {
            "turns": [{"role": "user", "content": {"text": "Hello, world!"}}]
        }

        hash1 = resumeservice.hash_prompt(prompt_dict)
        hash2 = resumeservice.hash_prompt(prompt_dict)

        assert hash1 == hash2
        assert len(hash1) == 16  # Should be 16 char hex string

    def test_hash_prompt_different_for_different_prompts(self):
        """Test that different prompts produce different hashes."""
        prompt1 = {"turns": [{"role": "user", "content": {"text": "Hello"}}]}
        prompt2 = {"turns": [{"role": "user", "content": {"text": "Goodbye"}}]}

        hash1 = resumeservice.hash_prompt(prompt1)
        hash2 = resumeservice.hash_prompt(prompt2)

        assert hash1 != hash2

    def test_get_completed_by_prompt_hash(self, set_seed_42):
        """Test that get_completed_by_prompt_hash returns correct data."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        result = resumeservice.get_completed_by_prompt_hash("probes.test.TestProbe")

        # Should have 2 completed attempts for this probe
        assert len(result) == 2

        # Each entry should be keyed by prompt hash
        for hash_key, attempt_data in result.items():
            assert len(hash_key) == 16  # 16 char hex hash
            assert "outputs" in attempt_data
            assert "prompt" in attempt_data

    def test_get_completed_by_prompt_hash_with_name_normalization(self, set_seed_42):
        """Test that get_completed_by_prompt_hash handles different probe name formats."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        # Should work with full name
        result1 = resumeservice.get_completed_by_prompt_hash("garak.probes.test.TestProbe")

        # Should work with short name
        result2 = resumeservice.get_completed_by_prompt_hash("probes.test.TestProbe")

        assert result1 == result2

    def test_get_completed_by_prompt_hash_returns_empty_for_unknown_probe(self, set_seed_42):
        """Test that get_completed_by_prompt_hash returns empty dict for unknown probe."""
        _config.transient.resume_file = "tests/_assets/resume_test_completed.report.jsonl"

        result = resumeservice.get_completed_by_prompt_hash("nonexistent.Probe")

        assert result == {}

    def test_extract_prompt_text(self):
        """Test that _extract_prompt_text correctly extracts text from prompt dict."""
        prompt = {
            "turns": [
                {"role": "user", "content": {"text": "Hello"}},
                {"role": "assistant", "content": {"text": "Hi there"}},
            ]
        }

        text = resumeservice._extract_prompt_text(prompt)

        assert text == "Hello|||Hi there"

    def test_extract_prompt_text_handles_string_content(self):
        """Test that _extract_prompt_text handles string content."""
        prompt = {
            "turns": [
                {"role": "user", "content": "Hello string"},
            ]
        }

        text = resumeservice._extract_prompt_text(prompt)

        assert text == "Hello string"


class TestProbeResumability:
    """Tests for probe resumability - documenting which probe types support resume."""

    def test_base_probe_supports_resume(self, set_seed_42):
        """Test that base Probe class uses resumeservice for prompt-based matching."""
        from garak.probes.base import Probe

        # Check that base Probe.probe() method references resumeservice
        import inspect
        source = inspect.getsource(Probe.probe)
        assert "resumeservice" in source, "Base Probe.probe() should use resumeservice"
        assert "get_completed_by_prompt_hash" in source, "Should use prompt-based matching"

    def test_treesearch_probe_does_not_call_super_probe(self):
        """Test that TreeSearchProbe has its own probe() - resume not automatically supported.

        TreeSearchProbe overrides probe() completely for tree traversal logic.
        Resume would need to be explicitly implemented in TreeSearchProbe.probe().
        """
        from garak.probes.base import TreeSearchProbe
        import inspect

        source = inspect.getsource(TreeSearchProbe.probe)
        # TreeSearchProbe.probe() does NOT call super().probe()
        assert "super().probe" not in source, "TreeSearchProbe has its own probe()"
        # And doesn't use resumeservice
        assert "resumeservice" not in source, "TreeSearchProbe doesn't use resumeservice"

    def test_iterative_probe_does_not_call_super_probe(self):
        """Test that IterativeProbe has its own probe() - resume not automatically supported.

        IterativeProbe overrides probe() completely for multi-turn conversation logic.
        Resume would need to be explicitly implemented in IterativeProbe.probe().
        """
        from garak.probes.base import IterativeProbe
        import inspect

        source = inspect.getsource(IterativeProbe.probe)
        # IterativeProbe.probe() does NOT call super().probe()
        assert "super().probe" not in source, "IterativeProbe has its own probe()"
        # And doesn't use resumeservice
        assert "resumeservice" not in source, "IterativeProbe doesn't use resumeservice"
