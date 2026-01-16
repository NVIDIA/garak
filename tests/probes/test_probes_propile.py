# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.probes.propile
from garak.attempt import Attempt, Message


class TestPIILeakProbeBase:
    """Tests for PIILeakProbeBase functionality."""

    def test_templates_loaded(self):
        """Test that templates are loaded from TSV file."""
        probe = garak.probes.propile.PIILeakTwin()
        assert len(probe.templates) > 0
        assert "twin_email" in probe.templates
        assert "twin_phone" in probe.templates
        assert "twin_address" in probe.templates

    def test_pii_records_loaded(self):
        """Test that PII records are loaded from JSONL file."""
        probe = garak.probes.propile.PIILeakTwin()
        assert len(probe.pii_records) > 0
        assert "name" in probe.pii_records[0]
        assert "email" in probe.pii_records[0]

    def test_attempt_prestore_hook_sets_triggers(self):
        """Test that attempt prestore hook sets triggers and pii_type."""
        probe = garak.probes.propile.PIILeakTwin()
        attempt = Attempt(prompt=Message(probe.prompts[0]))

        modified_attempt = probe._attempt_prestore_hook(attempt, 0)

        assert "triggers" in modified_attempt.notes
        assert "pii_type" in modified_attempt.notes
        assert isinstance(modified_attempt.notes["triggers"], list)


class TestPIILeakTwin:
    """Tests for PIILeakTwin probe."""

    def test_probe_attributes(self):
        """Test probe has required attributes."""
        probe = garak.probes.propile.PIILeakTwin()
        assert probe.active is False
        assert probe.goal == "extract PII using only the subject's name"
        assert probe.primary_detector == "propile.PIILeak"
        assert probe.lang == "en"

    def test_prompts_generated(self):
        """Test that prompts are generated from templates and PII data."""
        probe = garak.probes.propile.PIILeakTwin()
        assert len(probe.prompts) > 0
        assert len(probe.triggers) == len(probe.prompts)
        assert len(probe.pii_types) == len(probe.prompts)

    def test_prompt_contains_name(self):
        """Test that generated prompts contain names from PII data."""
        probe = garak.probes.propile.PIILeakTwin()
        names = [record["name"] for record in probe.pii_records]
        assert any(name in prompt for prompt in probe.prompts for name in names)

    def test_pii_types_valid(self):
        """Test that pii_types are valid categories."""
        probe = garak.probes.propile.PIILeakTwin()
        valid_types = {"email", "phone", "address"}
        assert all(pii_type in valid_types for pii_type in probe.pii_types)


class TestPIILeakTriplet:
    """Tests for PIILeakTriplet probe."""

    def test_probe_attributes(self):
        """Test probe has required attributes."""
        probe = garak.probes.propile.PIILeakTriplet()
        assert probe.active is False
        assert probe.goal == "extract PII using name and one auxiliary PII"

    def test_prompts_generated(self):
        """Test that prompts are generated."""
        probe = garak.probes.propile.PIILeakTriplet()
        assert len(probe.prompts) > 0

    def test_triplet_templates_used(self):
        """Test that triplet templates are loaded."""
        probe = garak.probes.propile.PIILeakTriplet()
        assert "triplet_email" in probe.templates
        assert "triplet_phone" in probe.templates
        assert "triplet_address" in probe.templates


class TestPIILeakQuadruplet:
    """Tests for PIILeakQuadruplet probe."""

    def test_probe_attributes(self):
        """Test probe has required attributes."""
        probe = garak.probes.propile.PIILeakQuadruplet()
        assert probe.active is False
        assert probe.goal == "extract PII using name and two auxiliary PIIs"

    def test_prompts_generated(self):
        """Test that prompts are generated."""
        probe = garak.probes.propile.PIILeakQuadruplet()
        assert len(probe.prompts) > 0

    def test_quadruplet_templates_used(self):
        """Test that quadruplet templates are loaded."""
        probe = garak.probes.propile.PIILeakQuadruplet()
        assert "quadruplet_email" in probe.templates
        assert "quadruplet_phone" in probe.templates
        assert "quadruplet_address" in probe.templates


class TestPIILeakUnstructured:
    """Tests for PIILeakUnstructured probe."""

    def test_probe_attributes(self):
        """Test probe has required attributes."""
        probe = garak.probes.propile.PIILeakUnstructured()
        assert probe.active is False
        assert probe.goal == "extract unstructured PII like relationships or affiliations"

    def test_default_relationships(self):
        """Test default relationships parameter."""
        probe = garak.probes.propile.PIILeakUnstructured()
        assert "father" in probe.relationships
        assert "mother" in probe.relationships
        assert "wife" in probe.relationships
        assert "husband" in probe.relationships

    def test_default_affiliations(self):
        """Test default affiliations parameter."""
        probe = garak.probes.propile.PIILeakUnstructured()
        assert "university" in probe.affiliations
        assert "employer" in probe.affiliations
        assert "organization" in probe.affiliations

    def test_unstructured_templates_loaded(self):
        """Test that unstructured templates are loaded."""
        probe = garak.probes.propile.PIILeakUnstructured()
        assert "unstructured_relation" in probe.templates
        assert "unstructured_university" in probe.templates
        assert "unstructured_employer" in probe.templates
        assert "unstructured_organization" in probe.templates
