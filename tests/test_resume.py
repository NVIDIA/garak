"""Tests for resume/checkpoint functionality integration."""

import json
import os
import tempfile
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


class TestResumeCliArgument:
    """Tests for the --resume CLI argument."""

    def test_resume_argument_file_not_found(self):
        """Test that --resume with nonexistent file raises error."""
        from garak import cli

        with pytest.raises(FileNotFoundError):
            cli.main(["--resume", "/nonexistent/file.jsonl", "-m", "test"])

    def test_resume_argument_registered(self):
        """Test that --resume argument is properly registered in CLI."""
        from garak.cli import command_options

        assert "resume" in command_options

    def test_resume_argument_invalid_file_extension(self, capsys):
        """Test that --resume with non-.report.jsonl file prints error message."""
        from garak import cli

        # Create a temp file with wrong extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("some content")
            temp_path = f.name

        try:
            # cli.main catches ValueError and prints it instead of raising
            cli.main(["--resume", temp_path, "-m", "test"])
            captured = capsys.readouterr()
            assert "must be a .report.jsonl file" in captured.out
        finally:
            os.unlink(temp_path)


class TestResumeIntegration:
    """Integration tests for the resume functionality."""

    def test_pending_detection_attempts_are_included(self, set_seed_42):
        """Test that pending detection attempts (status=1) are included in probe output.

        This test verifies with prompt-based matching:
        1. Completed attempts (status=2) are reused by prompt matching
        2. Pending detection attempts (status=1) are added to results for detection
        3. New prompts (no checkpoint entry) are sent for inference
        """
        from garak.probes.base import Probe
        from garak.attempt import Attempt, Message

        # Create a minimal probe subclass for testing
        class TestProbe(Probe):
            bcp47 = "en"
            goal = "test"
            doc_uri = ""
            prompts = ["test prompt 1", "test prompt 2", "test prompt 3"]
            primary_detector = "always.Pass"

            def __init__(self):
                super().__init__(config_root=_config)

        probe = TestProbe()
        # Get the actual probename that will be used for lookups
        actual_probename = probe.probename

        # Set up resumeservice with pending detection attempts
        # Create temp file with pending detection data
        with tempfile.NamedTemporaryFile(mode="w", suffix=".report.jsonl", delete=False) as f:
            # Write init and setup entries for validation
            f.write(json.dumps({"entry_type": "init", "garak_version": "0.13.4.pre1"}) + "\n")
            f.write(json.dumps({"entry_type": "start_run setup", "run.seed": 42}) + "\n")
            # Completed attempt (seq 0) - will be reused via prompt matching
            f.write(json.dumps({
                "entry_type": "attempt",
                "status": 2,
                "probe_classname": actual_probename.replace("garak.probes.", ""),
                "seq": 0,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "probe_params": {},
                "targets": [],
                "prompt": {"turns": [{"role": "user", "content": {"text": "test prompt 1"}}]},
                "outputs": [{"text": "response 0"}],
                "detector_results": {},
                "notes": {},
                "goal": "test",
                "conversations": [{"turns": [
                    {"role": "user", "content": {"text": "test prompt 1"}},
                    {"role": "assistant", "content": {"text": "response 0"}}
                ]}]
            }) + "\n")
            # Pending detection attempt (seq 1) - needs detection only
            f.write(json.dumps({
                "entry_type": "attempt",
                "status": 1,
                "probe_classname": actual_probename.replace("garak.probes.", ""),
                "seq": 1,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "probe_params": {},
                "targets": [],
                "prompt": {"turns": [{"role": "user", "content": {"text": "test prompt 2"}}]},
                "outputs": [{"text": "pending response"}],
                "detector_results": {},
                "notes": {},
                "goal": "test",
                "conversations": [{"turns": [
                    {"role": "user", "content": {"text": "test prompt 2"}},
                    {"role": "assistant", "content": {"text": "pending response"}}
                ]}]
            }) + "\n")
            temp_path = f.name

        try:
            # Enable resume mode
            _config.transient.resume_file = temp_path

            # Create mock generator
            mock_generator = MagicMock()
            mock_generator.name = "test_generator"

            # Create mock attempt for the new probe execution (prompt 3 needs inference)
            mock_attempt = MagicMock(spec=Attempt)
            mock_attempt.outputs = [Message(text="new response")]

            # Mock _execute_all to return only the new attempt (seq 2 - "test prompt 3")
            with patch.object(probe, "_execute_all") as mock_execute:
                mock_execute.return_value = [mock_attempt]

                # Run the probe
                results = probe.probe(mock_generator)

                # Should have 3 results:
                # - 1 reused (prompt 1 matched checkpoint completed)
                # - 1 from _execute_all (prompt 3 - new)
                # - 1 pending detection (prompt 2)
                assert len(results) == 3

                # Verify that pending detection attempt is included
                pending_attempt_found = False
                for result in results:
                    if hasattr(result, "seq") and result.seq == 1:
                        pending_attempt_found = True
                        # Verify it has the expected response from the checkpoint
                        if hasattr(result, "outputs") and result.outputs:
                            assert result.outputs[0].text == "pending response"
                        break

                assert pending_attempt_found, "Pending detection attempt (seq=1) should be in results"
        finally:
            os.unlink(temp_path)

    def test_completed_attempts_are_reused(self, set_seed_42):
        """Test that completed attempts (status=2) are reused via prompt matching during resume.

        With prompt-based matching, completed attempts are reused (outputs copied)
        instead of being skipped entirely. This test verifies:
        1. Prompts that match the checkpoint are reused (no inference needed)
        2. The outputs from the checkpoint are copied to the reused attempts
        3. _execute_all is called only with non-matching prompts
        """
        from garak.probes.base import Probe

        # Prompts must match what's in the checkpoint for prompt-based matching
        class TestProbe(Probe):
            bcp47 = "en"
            goal = "test"
            doc_uri = ""
            prompts = ["prompt 0", "prompt 1", "prompt 2"]  # Match checkpoint prompts
            primary_detector = "always.Pass"

            def __init__(self):
                super().__init__(config_root=_config)

        probe = TestProbe()
        actual_probename = probe.probename

        # Create temp file with all attempts completed
        with tempfile.NamedTemporaryFile(mode="w", suffix=".report.jsonl", delete=False) as f:
            # Write init and setup entries for validation
            f.write(json.dumps({"entry_type": "init", "garak_version": "0.13.4.pre1"}) + "\n")
            f.write(json.dumps({"entry_type": "start_run setup", "run.seed": 42}) + "\n")
            for seq in range(3):
                f.write(json.dumps({
                    "entry_type": "attempt",
                    "status": 2,
                    "probe_classname": actual_probename.replace("garak.probes.", ""),
                    "seq": seq,
                    "uuid": f"0000000{seq}-0000-0000-0000-000000000000",
                    "probe_params": {},
                    "targets": [],
                    "prompt": {"turns": [{"role": "user", "content": {"text": f"prompt {seq}"}}]},
                    "outputs": [{"text": f"response {seq}"}],
                    "detector_results": {},
                    "notes": {},
                    "goal": "test",
                    "conversations": [{"turns": [
                        {"role": "user", "content": {"text": f"prompt {seq}"}},
                        {"role": "assistant", "content": {"text": f"response {seq}"}}
                    ]}]
                }) + "\n")
            temp_path = f.name

        try:
            _config.transient.resume_file = temp_path

            mock_generator = MagicMock()
            mock_generator.name = "test_generator"

            with patch.object(probe, "_execute_all") as mock_execute:
                mock_execute.return_value = []  # No new attempts to execute

                results = probe.probe(mock_generator)

                # _execute_all should be called with empty list since all are reused
                mock_execute.assert_called_once()
                call_args = mock_execute.call_args[0][0]
                assert len(call_args) == 0, "Should have no attempts to execute when all are reused"

                # Results should have 3 reused attempts with outputs from checkpoint
                assert len(results) == 3, "Should have 3 reused attempts"

                # Verify outputs were copied from checkpoint
                for i, result in enumerate(results):
                    assert result.outputs[0].text == f"response {i}"
        finally:
            os.unlink(temp_path)
