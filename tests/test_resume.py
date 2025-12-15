"""Tests for resume/checkpoint functionality."""

import json
import os
import tempfile
import pytest

from garak import _config
from garak.command import load_checkpoint
from garak.attempt import Attempt, ATTEMPT_NEW, ATTEMPT_STARTED, ATTEMPT_COMPLETE


class TestLoadCheckpoint:
    """Tests for the load_checkpoint function."""

    def test_load_checkpoint_valid_jsonl(self):
        """Test loading a valid JSONL report file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            # Write setup entry
            f.write(
                json.dumps(
                    {
                        "entry_type": "start_run setup",
                        "plugins.probe_spec": "probes.test.TestProbe",
                    }
                )
                + "\n"
            )
            # Write completed attempts
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 0,
                    }
                )
                + "\n"
            )
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 1,
                    }
                )
                + "\n"
            )
            # status=2 for another probe
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.other.OtherProbe",
                        "seq": 0,
                    }
                )
                + "\n"
            )
            temp_path = f.name

        try:
            completed, pending_detection, probe_spec = load_checkpoint(temp_path)

            assert probe_spec == "probes.test.TestProbe"
            assert "probes.test.TestProbe" in completed
            assert completed["probes.test.TestProbe"] == {0, 1}
            # OtherProbe also has status=2, so it should be counted
            assert "probes.other.OtherProbe" in completed
            assert completed["probes.other.OtherProbe"] == {0}
            # No pending detection attempts (all are status=2)
            assert pending_detection == {}
        finally:
            os.unlink(temp_path)

    def test_load_checkpoint_empty_file(self):
        """Test loading an empty JSONL file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            temp_path = f.name

        try:
            completed, pending_detection, probe_spec = load_checkpoint(temp_path)

            assert completed == {}
            assert pending_detection == {}
            assert probe_spec is None
        finally:
            os.unlink(temp_path)

    def test_load_checkpoint_malformed_json(self):
        """Test that malformed JSON lines are skipped gracefully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            # Valid entry
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 0,
                    }
                )
                + "\n"
            )
            # Malformed JSON
            f.write("this is not valid json\n")
            # Another valid entry
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 1,
                    }
                )
                + "\n"
            )
            temp_path = f.name

        try:
            completed, pending_detection, probe_spec = load_checkpoint(temp_path)

            # Should have both valid entries despite malformed line
            assert completed["probes.test.TestProbe"] == {0, 1}
        finally:
            os.unlink(temp_path)

    def test_load_checkpoint_file_not_found(self):
        """Test that FileNotFoundError is raised for missing file."""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_checkpoint("/nonexistent/path/to/file.jsonl")

        assert "Resume file not found" in str(exc_info.value)

    def test_load_checkpoint_only_counts_status_2(self):
        """Test that only status=2 (complete) attempts are counted as completed."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            # Status 0 = pending/new, should be ignored
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 0,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 0,
                    }
                )
                + "\n"
            )
            # Status 1 = started (response received but no detection), goes to pending_detection
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 1,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 1,
                        "prompt": {
                            "turns": [{"role": "user", "content": {"text": "test"}}]
                        },
                        "outputs": [{"text": "response"}],
                    }
                )
                + "\n"
            )
            # Status 2 = complete (detection done), should be counted
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 2,
                    }
                )
                + "\n"
            )
            temp_path = f.name

        try:
            completed, pending_detection, _ = load_checkpoint(temp_path)

            # Only seq=2 should be completed (status=2)
            assert completed["probes.test.TestProbe"] == {2}
            # seq=1 (status=1) should be in pending_detection
            assert "probes.test.TestProbe" in pending_detection
            assert 1 in pending_detection["probes.test.TestProbe"]
        finally:
            os.unlink(temp_path)

    def test_load_checkpoint_ignores_non_attempt_entries(self):
        """Test that non-attempt entry types are ignored for completion tracking."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"entry_type": "init", "garak_version": "1.0.0"}) + "\n")
            f.write(
                json.dumps(
                    {"entry_type": "eval", "probe_classname": "probes.test.TestProbe"}
                )
                + "\n"
            )
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 0,
                    }
                )
                + "\n"
            )
            temp_path = f.name

        try:
            completed, pending_detection, _ = load_checkpoint(temp_path)

            # Only the attempt entry should be counted
            assert len(completed) == 1
            assert completed["probes.test.TestProbe"] == {0}
            assert pending_detection == {}
        finally:
            os.unlink(temp_path)

    def test_load_checkpoint_handles_blank_lines(self):
        """Test that blank lines in the file are handled gracefully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("\n")  # Blank line
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 0,
                    }
                )
                + "\n"
            )
            f.write("   \n")  # Whitespace-only line
            f.write(
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "probe_classname": "probes.test.TestProbe",
                        "seq": 1,
                    }
                )
                + "\n"
            )
            temp_path = f.name

        try:
            completed, pending_detection, _ = load_checkpoint(temp_path)

            assert completed["probes.test.TestProbe"] == {0, 1}
        finally:
            os.unlink(temp_path)

    def test_load_checkpoint_pending_detection_stores_full_data(self):
        """Test that status=1 attempts store full attempt data for reconstruction."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            attempt_data = {
                "entry_type": "attempt",
                "status": 1,
                "probe_classname": "probes.test.TestProbe",
                "seq": 0,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "prompt": {
                    "turns": [{"role": "user", "content": {"text": "test prompt"}}]
                },
                "outputs": [{"text": "test response"}],
                "conversations": [
                    {
                        "turns": [
                            {"role": "user", "content": {"text": "test prompt"}},
                            {"role": "assistant", "content": {"text": "test response"}},
                        ]
                    }
                ],
                "targets": ["target1"],
                "goal": "test goal",
            }
            f.write(json.dumps(attempt_data) + "\n")
            temp_path = f.name

        try:
            completed, pending_detection, _ = load_checkpoint(temp_path)

            assert completed == {}
            assert "probes.test.TestProbe" in pending_detection
            assert 0 in pending_detection["probes.test.TestProbe"]
            # Verify full data is stored
            stored_data = pending_detection["probes.test.TestProbe"][0]
            assert stored_data["uuid"] == "12345678-1234-1234-1234-123456789abc"
            assert stored_data["goal"] == "test goal"
            assert stored_data["targets"] == ["target1"]
        finally:
            os.unlink(temp_path)


class TestAttemptFromDict:
    """Tests for the Attempt.from_dict() method."""

    def test_from_dict_basic(self):
        """Test basic reconstruction of an Attempt from dict."""
        data = {
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "status": 1,
            "probe_classname": "probes.test.TestProbe",
            "seq": 5,
            "goal": "test goal",
            "targets": ["target1", "target2"],
            "probe_params": {"param1": "value1"},
            "notes": {"note1": "value1"},
            "detector_results": {},
            "conversations": [
                {
                    "turns": [
                        {"role": "user", "content": {"text": "test prompt"}},
                        {"role": "assistant", "content": {"text": "test response"}},
                    ]
                }
            ],
            "reverse_translation_outputs": [],
        }

        attempt = Attempt.from_dict(data)

        assert str(attempt.uuid) == "12345678-1234-1234-1234-123456789abc"
        assert attempt.status == ATTEMPT_STARTED
        assert attempt.probe_classname == "probes.test.TestProbe"
        assert attempt.seq == 5
        assert attempt.goal == "test goal"
        assert attempt.targets == ["target1", "target2"]
        assert attempt.probe_params == {"param1": "value1"}
        assert attempt.notes == {"note1": "value1"}

    def test_from_dict_reconstructs_conversations(self):
        """Test that conversations are properly reconstructed."""
        data = {
            "status": 1,
            "probe_classname": "probes.test.TestProbe",
            "seq": 0,
            "conversations": [
                {
                    "turns": [
                        {"role": "user", "content": {"text": "Hello"}},
                        {"role": "assistant", "content": {"text": "Hi there!"}},
                    ]
                }
            ],
            "reverse_translation_outputs": [],
        }

        attempt = Attempt.from_dict(data)

        assert len(attempt.conversations) == 1
        assert len(attempt.conversations[0].turns) == 2
        assert attempt.conversations[0].turns[0].role == "user"
        assert attempt.conversations[0].turns[0].content.text == "Hello"
        assert attempt.conversations[0].turns[1].role == "assistant"
        assert attempt.conversations[0].turns[1].content.text == "Hi there!"

    def test_from_dict_outputs_accessible(self):
        """Test that outputs are accessible from reconstructed attempt."""
        data = {
            "status": 1,
            "probe_classname": "probes.test.TestProbe",
            "seq": 0,
            "conversations": [
                {
                    "turns": [
                        {"role": "user", "content": {"text": "test prompt"}},
                        {"role": "assistant", "content": {"text": "response 1"}},
                    ]
                },
                {
                    "turns": [
                        {"role": "user", "content": {"text": "test prompt"}},
                        {"role": "assistant", "content": {"text": "response 2"}},
                    ]
                },
            ],
            "reverse_translation_outputs": [],
        }

        attempt = Attempt.from_dict(data)

        outputs = attempt.outputs
        assert len(outputs) == 2
        assert outputs[0].text == "response 1"
        assert outputs[1].text == "response 2"

    def test_from_dict_with_missing_optional_fields(self):
        """Test reconstruction with minimal required fields."""
        data = {
            "status": 1,
            "probe_classname": "probes.test.TestProbe",
            "seq": 0,
            "conversations": [],
            "reverse_translation_outputs": [],
        }

        attempt = Attempt.from_dict(data)

        assert attempt.status == ATTEMPT_STARTED
        assert attempt.probe_classname == "probes.test.TestProbe"
        assert attempt.seq == 0
        assert attempt.targets == []
        assert attempt.notes == {}
        assert attempt.goal is None


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
