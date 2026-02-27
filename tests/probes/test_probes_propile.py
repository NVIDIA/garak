# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import garak.probes.propile
from garak.attempt import Attempt, Message
from garak.exception import PluginConfigurationError

# Test PII data fixture
TEST_PII_RECORDS = [
    {
        "name": "John Smith",
        "email": "john.smith@example.com",
        "phone": "555-123-4567",
        "address": "123 Main St, Anytown, USA",
        "employer": "Acme Corp",
    },
    {
        "name": "Jane Doe",
        "email": "jane.doe@example.org",
        "phone": "555-987-6543",
        "address": "456 Oak Ave, Somewhere, USA",
        "employer": "Tech Inc",
    },
    {
        "name": "Bob Wilson",
        "email": "bob.wilson@test.net",
        "phone": "555-555-5555",
        "address": "789 Pine Rd, Nowhere, USA",
        "organization": "Open Source Foundation",
    },
]


@pytest.fixture
def pii_data_file(tmp_path):
    """Create a temporary PII data file for testing."""
    pii_file = tmp_path / "test_pii.jsonl"
    with open(pii_file, "w", encoding="utf-8") as f:
        for record in TEST_PII_RECORDS:
            f.write(json.dumps(record) + "\n")
    return pii_file


@pytest.fixture
def mock_reportfile():
    """Mock the reportfile to avoid writing during tests."""
    mock_file = MagicMock()
    mock_file.closed = False
    return mock_file


class TestPIILeakProbeBase:
    """Tests for PIILeakProbeBase functionality."""

    def test_templates_loaded(self, pii_data_file, mock_reportfile):
        """Test that templates are loaded from TSV file."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert len(probe.templates) > 0
        assert "twin_email" in probe.templates
        assert "twin_phone" in probe.templates
        assert "twin_address" in probe.templates

    def test_pii_records_loaded(self, pii_data_file, mock_reportfile):
        """Test that PII records are loaded from JSONL file."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert len(probe.pii_records) == 3
        assert "name" in probe.pii_records[0]
        assert "email" in probe.pii_records[0]

    def test_attempt_prestore_hook_sets_triggers(self, pii_data_file, mock_reportfile):
        """Test that attempt prestore hook sets triggers, pii_type, and pii_data_source."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        attempt = Attempt(prompt=Message(probe.prompts[0]))

        modified_attempt = probe._attempt_prestore_hook(attempt, 0)

        assert "triggers" in modified_attempt.notes
        assert "pii_type" in modified_attempt.notes
        assert "pii_data_source" in modified_attempt.notes
        assert isinstance(modified_attempt.notes["triggers"], list)
        assert str(pii_data_file) in modified_attempt.notes["pii_data_source"]

    def test_pii_data_init_written_to_report(self, pii_data_file, mock_reportfile):
        """Test that pii_data_init entry is written to reportfile."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )

        # Check that write was called with pii_data_init entry
        write_calls = mock_reportfile.write.call_args_list
        assert len(write_calls) > 0

        written_data = json.loads(write_calls[0][0][0].strip())
        assert written_data["entry_type"] == "pii_data_init"
        assert written_data["pii_data_name"] == "test_pii"
        assert written_data["entries"] == 3


class TestPIILeakTwin:
    """Tests for PIILeakTwin probe."""

    def test_probe_attributes(self, pii_data_file, mock_reportfile):
        """Test probe has required attributes."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert probe.active is False
        assert probe.goal == "extract PII using only the subject's name"
        assert probe.primary_detector == "propile.PIILeak"
        assert probe.lang == "en"

    def test_prompts_generated(self, pii_data_file, mock_reportfile):
        """Test that prompts are generated from templates and PII data."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert len(probe.prompts) > 0
        assert len(probe.triggers) == len(probe.prompts)
        assert len(probe.pii_types) == len(probe.prompts)

    def test_prompt_contains_name(self, pii_data_file, mock_reportfile):
        """Test that generated prompts contain names from PII data."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        names = [record["name"] for record in probe.pii_records]
        assert any(name in prompt for prompt in probe.prompts for name in names)

    def test_pii_types_valid(self, pii_data_file, mock_reportfile):
        """Test that pii_types are valid categories."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTwin(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTwin": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        valid_types = {"email", "phone", "address"}
        assert all(pii_type in valid_types for pii_type in probe.pii_types)


class TestPIILeakTriplet:
    """Tests for PIILeakTriplet probe."""

    def test_probe_attributes(self, pii_data_file, mock_reportfile):
        """Test probe has required attributes."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTriplet(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTriplet": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert probe.active is False
        assert probe.goal == "extract PII using name and one auxiliary PII"

    def test_prompts_generated(self, pii_data_file, mock_reportfile):
        """Test that prompts are generated."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTriplet(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTriplet": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert len(probe.prompts) > 0

    def test_triplet_templates_used(self, pii_data_file, mock_reportfile):
        """Test that triplet templates are loaded."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakTriplet(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakTriplet": {"pii_data_path": str(pii_data_file)}
                            }
                        }
                    )
                )
            )
        assert "triplet_email" in probe.templates
        assert "triplet_phone" in probe.templates
        assert "triplet_address" in probe.templates


class TestPIILeakQuadruplet:
    """Tests for PIILeakQuadruplet probe."""

    def test_probe_attributes(self, pii_data_file, mock_reportfile):
        """Test probe has required attributes."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakQuadruplet(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakQuadruplet": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert probe.active is False
        assert probe.goal == "extract PII using name and two auxiliary PIIs"

    def test_prompts_generated(self, pii_data_file, mock_reportfile):
        """Test that prompts are generated."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakQuadruplet(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakQuadruplet": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert len(probe.prompts) > 0

    def test_quadruplet_templates_used(self, pii_data_file, mock_reportfile):
        """Test that quadruplet templates are loaded."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakQuadruplet(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakQuadruplet": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert "quadruplet_email" in probe.templates
        assert "quadruplet_phone" in probe.templates
        assert "quadruplet_address" in probe.templates


class TestPIILeakUnstructured:
    """Tests for PIILeakUnstructured probe."""

    def test_probe_attributes(self, pii_data_file, mock_reportfile):
        """Test probe has required attributes."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakUnstructured(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakUnstructured": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert probe.active is False
        assert (
            probe.goal == "extract unstructured PII like relationships or affiliations"
        )

    def test_default_relationships(self, pii_data_file, mock_reportfile):
        """Test default relationships parameter."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakUnstructured(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakUnstructured": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert "father" in probe.relationships
        assert "mother" in probe.relationships
        assert "wife" in probe.relationships
        assert "husband" in probe.relationships

    def test_default_affiliations(self, pii_data_file, mock_reportfile):
        """Test default affiliations parameter."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakUnstructured(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakUnstructured": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert "university" in probe.affiliations
        assert "employer" in probe.affiliations
        assert "organization" in probe.affiliations

    def test_unstructured_templates_loaded(self, pii_data_file, mock_reportfile):
        """Test that unstructured templates are loaded."""
        with patch("garak._config.transient.reportfile", mock_reportfile):
            probe = garak.probes.propile.PIILeakUnstructured(
                config_root=MagicMock(
                    plugins=MagicMock(
                        probes={
                            "propile": {
                                "PIILeakUnstructured": {
                                    "pii_data_path": str(pii_data_file)
                                }
                            }
                        }
                    )
                )
            )
        assert "unstructured_relation" in probe.templates
        assert "unstructured_university" in probe.templates
        assert "unstructured_employer" in probe.templates
        assert "unstructured_organization" in probe.templates


class TestMissingPIIData:
    """Tests for behavior when PII data file is missing."""

    def test_raises_when_file_missing(self, tmp_path, mock_reportfile):
        """Test that PluginConfigurationError is raised when PII data file doesn't exist."""
        nonexistent_path = tmp_path / "nonexistent.jsonl"
        with patch("garak._config.transient.reportfile", mock_reportfile):
            with pytest.raises(PluginConfigurationError):
                garak.probes.propile.PIILeakTwin(
                    config_root=MagicMock(
                        plugins=MagicMock(
                            probes={
                                "propile": {
                                    "PIILeakTwin": {
                                        "pii_data_path": str(nonexistent_path)
                                    }
                                }
                            }
                        )
                    )
                )
