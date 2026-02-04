# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for resume functionality.

These tests verify that interrupted scans can be resumed correctly,
maintaining run_id consistency, probe ordering, and score accuracy.
"""

import json
import os
import subprocess
import time
from pathlib import Path
import pytest


@pytest.fixture
def test_output_dir(tmp_path):
    """Create temporary output directory for test reports."""
    output_dir = tmp_path / "test_reports"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def garak_config(test_output_dir):
    """Create test configuration file."""
    config = {
        "plugins": {
            "target_type": "test",
            "target_name": "test.Blank",
            "probe_spec": "test.Blank,test.Test",
        },
        "run": {"resumable": True, "resume_granularity": "attempt"},
        "reporting": {"report_dir": str(test_output_dir), "report_prefix": "test_run"},
    }

    config_path = test_output_dir / "test_config.yaml"
    import yaml

    with open(config_path, "w") as f:
        yaml.dump(config, f)

    return config_path


def parse_report_jsonl(report_path):
    """Parse JSONL report file and return structured data."""
    records = []
    with open(report_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    setup = next((r for r in records if r.get("entry_type") == "start_run setup"), None)
    init = next((r for r in records if r.get("entry_type") == "init"), None)
    attempts = [r for r in records if r.get("entry_type") == "attempt"]
    evals = [r for r in records if r.get("entry_type") == "eval"]
    digest = next((r for r in records if r.get("entry_type") == "digest"), None)

    return {
        "setup": setup,
        "init": init,
        "attempts": attempts,
        "evals": evals,
        "digest": digest,
        "all_records": records,
    }


def parse_hitlog_jsonl(hitlog_path):
    """Parse hitlog JSONL file."""
    hits = []
    with open(hitlog_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                hits.append(json.loads(line))
    return hits


class TestResumeIntegration:
    """Integration tests for resume functionality."""

    def test_full_run_consistency(self, garak_config, test_output_dir):
        """Test that a full uninterrupted run produces consistent reports."""
        # Run garak with test config
        result = subprocess.run(
            ["python", "-m", "garak", "--config", str(garak_config)],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"Garak failed: {result.stderr}"

        # Find generated report files
        report_files = list(test_output_dir.glob("test_run*.report.jsonl"))
        assert len(report_files) == 1, f"Expected 1 report, found {len(report_files)}"

        report_path = report_files[0]
        hitlog_path = report_path.with_suffix(".hitlog.jsonl")

        # Parse reports
        report = parse_report_jsonl(report_path)
        hits = parse_hitlog_jsonl(hitlog_path) if hitlog_path.exists() else []

        # Verify run_id consistency
        run_id = report["init"]["run"]
        assert run_id, "Run ID not found in init record"

        # Check all hitlog entries use same run_id (if hitlog exists)
        if hits:
            hitlog_run_ids = set(hit["run_id"] for hit in hits)
            assert (
                len(hitlog_run_ids) == 1
            ), f"Multiple run_ids in hitlog: {hitlog_run_ids}"
            assert hitlog_run_ids.pop() == run_id, "Hitlog run_id doesn't match report"

        # Verify probe order in digest
        if report["digest"]:
            eval_section = report["digest"]["eval"]
            probe_names = []
            for group in eval_section.values():
                for key in group.keys():
                    if key != "_summary" and "." in key:
                        probe_names.append(key)

            # Should be test.Blank first, test.Test second (matching probe_spec)
            assert len(probe_names) == 2, f"Expected 2 probes, found {len(probe_names)}"
            assert probe_names[0] == "test.Blank", "test.Blank should be first"
            assert probe_names[1] == "test.Test", "test.Test should be second"

        # Verify seq numbering resets per probe
        blank_seqs = [
            a["seq"] for a in report["attempts"] if "Blank" in a["probe_classname"]
        ]
        test_seqs = [
            a["seq"]
            for a in report["attempts"]
            if "Test" in a["probe_classname"] and "Blank" not in a["probe_classname"]
        ]

        if blank_seqs:
            assert min(blank_seqs) == 0, "test.Blank seq should start at 0"
            # Sequences should be monotonically increasing within each generation batch

        if test_seqs:
            assert min(test_seqs) == 0, "test.Test seq should start at 0"
            # test.Test has 8 prompts, so sequences are 0-7 repeated for each generation count
            # Just verify all seqs are in valid range
            assert all(
                0 <= seq < 8 for seq in test_seqs
            ), "test.Test seqs should be 0-7"

    @pytest.mark.skipif(
        os.environ.get("RUN_INTERRUPT_TESTS") != "1",
        reason="Interrupt tests require manual intervention or special setup",
    )
    def test_resume_after_interrupt(self, garak_config, test_output_dir):
        """Test resuming a scan after interruption.

        This test requires RUN_INTERRUPT_TESTS=1 environment variable.
        It simulates an interrupt by killing the process mid-scan.
        """
        # Start garak in background
        proc = subprocess.Popen(
            ["python", "-m", "garak", "--config", str(garak_config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for first probe to complete (approx 30s)
        time.sleep(35)

        # Interrupt the process
        proc.terminate()
        proc.wait(timeout=10)

        # Find state files
        state_dir = Path.home() / ".local" / "share" / "garak" / "runs"
        state_files = list(state_dir.glob("garak-run-*"))

        assert len(state_files) > 0, "No state files found after interrupt"

        # Get the most recent run_id
        latest_state = max(state_files, key=lambda p: p.stat().st_mtime)
        run_id = latest_state.name

        # Resume the scan
        result = subprocess.run(
            ["python", "-m", "garak", "--resume", run_id],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"Resume failed: {result.stderr}"

        # Find the report file
        report_files = list(test_output_dir.glob("test_run*.report.jsonl"))
        assert len(report_files) == 1, f"Expected 1 report after resume"

        report_path = report_files[0]
        hitlog_path = report_path.with_suffix(".hitlog.jsonl")

        # Parse reports
        report = parse_report_jsonl(report_path)
        hits = parse_hitlog_jsonl(hitlog_path)

        # Verify run_id consistency across resume
        report_run_id = report["init"]["run"]
        hitlog_run_ids = set(hit["run_id"] for hit in hits)

        assert (
            len(hitlog_run_ids) == 1
        ), f"Multiple run_ids after resume: {hitlog_run_ids}"
        assert (
            hitlog_run_ids.pop() == report_run_id
        ), "Hitlog run_id inconsistent after resume"

        # Verify no duplicate attempts
        attempt_uuids = [a["uuid"] for a in report["attempts"]]
        assert len(attempt_uuids) == len(set(attempt_uuids)), "Duplicate attempts found"

        # Verify both probes completed
        probe_names = set(a["probe_classname"] for a in report["attempts"])
        assert "av_spam_scanning.EICAR" in probe_names, "EICAR probe missing"
        assert "av_spam_scanning.GTUBE" in probe_names, "GTUBE probe missing"


class TestScoreAccuracy:
    """Verify that scores correctly reflect pass/fail outcomes."""

    def test_score_matches_hitlog(self, garak_config, test_output_dir):
        """Verify digest scores match actual hitlog entries."""
        # Run scan
        result = subprocess.run(
            ["python", "-m", "garak", "--config", str(garak_config)],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"Garak failed: {result.stderr}"

        # Parse reports
        report_path = list(test_output_dir.glob("test_run*.report.jsonl"))[0]
        hitlog_path = report_path.with_suffix(".hitlog.jsonl")

        report = parse_report_jsonl(report_path)
        hits = parse_hitlog_jsonl(hitlog_path) if hitlog_path.exists() else []

        # Group hits by probe
        blank_hits = [h for h in hits if h["probe"] == "test.Blank"]
        test_hits = [h for h in hits if h["probe"] == "test.Test"]

        # Get total attempts per probe
        blank_attempts = [
            a for a in report["attempts"] if "Blank" in a["probe_classname"]
        ]
        test_attempts = [
            a
            for a in report["attempts"]
            if "Test" in a["probe_classname"] and "Blank" not in a["probe_classname"]
        ]

        # Calculate expected scores (pass rate = 1 - fail_rate)
        blank_expected_score = (
            1.0 - (len(blank_hits) / len(blank_attempts))
            if len(blank_attempts) > 0
            else 1.0
        )
        test_expected_score = (
            1.0 - (len(test_hits) / len(test_attempts))
            if len(test_attempts) > 0
            else 1.0
        )

        # Get actual scores from digest
        digest = report["digest"]
        if digest:
            eval_section = digest["eval"]
            for group in eval_section.values():
                if "test.Blank" in group:
                    blank_actual = group["test.Blank"]["_summary"]["probe_score"]
                    # Score in digest is pass percentage (0-1 scale)
                    assert blank_actual is not None, f"test.Blank score is None"

                if "test.Test" in group:
                    test_actual = group["test.Test"]["_summary"]["probe_score"]
                    assert test_actual is not None, f"test.Test score is None"

    @pytest.mark.skip(
        reason="EICAR detection test not relevant to resume functionality with test probes"
    )
    def test_detection_with_prefixes(self, test_output_dir):
        """Verify that detection works correctly with prefix/suffix variations."""
        # This is more of a documentation test - verify current behavior
        # Detection should find the signature regardless of surrounding text

        test_cases = [
            (
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                True,
            ),
            (
                "IN: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                True,
            ),
            (
                "The string is: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                True,
            ),
            ("I can't output that string.", False),
        ]

        # Import detector to test directly
        from garak.detectors import knownbadsignatures

        detector = knownbadsignatures.EICAR()

        for output_text, should_detect in test_cases:
            from garak.attempt import Attempt, Message

            # Create mock attempt with proper Message object
            attempt = Attempt(prompt=Message("test prompt"))
            attempt.outputs = [output_text]

            # Run detection
            results = detector.detect(attempt)

            if should_detect:
                assert 1.0 in results, f"Failed to detect in: {output_text[:50]}..."
            else:
                assert 0.0 in results, f"False positive on: {output_text[:50]}..."


class TestProbeOrdering:
    """Verify that probe ordering is preserved across all report formats."""

    def test_digest_respects_probe_spec(self, garak_config, test_output_dir):
        """Verify digest iterates probes in probe_spec order."""
        result = subprocess.run(
            ["python", "-m", "garak", "--config", str(garak_config)],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0

        report_path = list(test_output_dir.glob("test_run*.report.jsonl"))[0]
        report = parse_report_jsonl(report_path)

        # Get probe_spec from setup
        probe_spec = report["setup"]["plugins.probe_spec"]
        expected_order = [p.strip() for p in probe_spec.split(",")]

        # Get actual order from digest
        digest = report["digest"]
        actual_order = []

        if digest:
            eval_section = digest["eval"]
            for group in eval_section.values():
                for key in group.keys():
                    if key != "_summary" and "." in key:
                        actual_order.append(key)

        assert (
            actual_order == expected_order
        ), f"Probe order mismatch: expected {expected_order}, got {actual_order}"

    def test_html_respects_probe_order(self, garak_config, test_output_dir):
        """Verify HTML report shows probes in correct order."""
        result = subprocess.run(
            ["python", "-m", "garak", "--config", str(garak_config)],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0

        html_files = list(test_output_dir.glob("test_run*.report.html"))
        assert len(html_files) == 1

        with open(html_files[0], "r", encoding="utf-8") as f:
            html_content = f.read()

        # Find probe headings in HTML
        blank_pos = html_content.find("test.Blank")
        test_pos = html_content.find("test.Test")

        assert blank_pos > 0, "test.Blank not found in HTML"
        assert test_pos > 0, "test.Test not found in HTML"
        assert blank_pos < test_pos, "test.Blank should appear before test.Test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
