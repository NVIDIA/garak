# SPDX-FileCopyrightText: Copyright (c) 2025 Nathan Maine
# SPDX-License-Identifier: Apache-2.0

"""Tests for compliance-focused probes.

Validates probe initialization, prompt loading from data files,
and attribute requirements for regulatory vulnerability probes.
"""

import pytest

from garak import _plugins
import garak.probes.base
import garak.probes.compliance

COMPLIANCE_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.compliance")
]


@pytest.mark.parametrize("classname", COMPLIANCE_PROBES)
def test_compliance_probe_loads(classname):
    p = _plugins.load_plugin(classname)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("classname", COMPLIANCE_PROBES)
def test_compliance_probe_has_prompts(classname):
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) > 0, f"{classname} has no prompts"


@pytest.mark.parametrize("classname", COMPLIANCE_PROBES)
def test_compliance_probe_has_required_attributes(classname):
    p = _plugins.load_plugin(classname)
    assert p.lang == "en"
    assert p.goal != ""
    assert p.primary_detector != ""
    assert p.active is True


class TestComplianceHallucination:
    def test_prompt_count(self):
        p = _plugins.load_plugin("probes.compliance.ComplianceHallucination")
        assert len(p.prompts) == 25  # 5 data files * 5 prompts each

    def test_prompts_contain_fake_controls(self):
        p = _plugins.load_plugin("probes.compliance.ComplianceHallucination")
        assert any("3.99.1" in prompt for prompt in p.prompts)
        assert any("ZZ-99" in prompt for prompt in p.prompts)
        assert any("Level 5" in prompt for prompt in p.prompts)
        assert any("7099" in prompt for prompt in p.prompts)

    def test_primary_detector(self):
        p = _plugins.load_plugin("probes.compliance.ComplianceHallucination")
        assert p.primary_detector == "compliance.FabricatedCitation"


class TestCompliancePIILeak:
    def test_prompt_count(self):
        p = _plugins.load_plugin("probes.compliance.CompliancePIILeak")
        assert len(p.prompts) == 15  # 3 data files * 5 prompts each

    def test_prompts_cover_extraction_strategies(self):
        p = _plugins.load_plugin("probes.compliance.CompliancePIILeak")
        prompts_text = " ".join(p.prompts).lower()
        assert "ssn" in prompts_text or "social security" in prompts_text
        assert "email" in prompts_text
        assert "assessor" in prompts_text or "c3pao" in prompts_text


class TestPolicyBypass:
    def test_prompt_count(self):
        p = _plugins.load_plugin("probes.compliance.PolicyBypass")
        assert len(p.prompts) == 20  # 4 data files * 5 prompts each

    def test_includes_unicode_obfuscation(self):
        p = _plugins.load_plugin("probes.compliance.PolicyBypass")
        obfuscated = [pr for pr in p.prompts if any(ord(c) > 127 for c in pr)]
        assert len(obfuscated) == 5

    def test_primary_detector(self):
        p = _plugins.load_plugin("probes.compliance.PolicyBypass")
        assert p.primary_detector == "compliance.BypassInstructions"
        assert "owasp:llm01" in p.tags


class TestComplianceStatusFabrication:
    def test_prompt_count(self):
        p = _plugins.load_plugin("probes.compliance.ComplianceStatusFabrication")
        assert len(p.prompts) == 20  # 4 data files * 5 prompts each

    def test_prompts_cover_fabrication_strategies(self):
        p = _plugins.load_plugin("probes.compliance.ComplianceStatusFabrication")
        prompts_text = " ".join(p.prompts).lower()
        assert "certificate" in prompts_text or "certif" in prompts_text
        assert "score" in prompts_text
        assert "cmmc" in prompts_text
