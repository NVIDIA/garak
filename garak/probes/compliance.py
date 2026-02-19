# SPDX-FileCopyrightText: Copyright (c) 2025 Nathan Maine
# SPDX-License-Identifier: Apache-2.0

"""**Compliance-focused probes for regulated industry LLM deployments.**

Probes targeting compliance-specific vulnerabilities in LLMs used for
regulatory guidance (CMMC, NIST, HIPAA, DFARS). These probes test whether
models fabricate regulatory citations, leak sensitive data, help circumvent
security controls, or falsely assert compliance status.

Designed for use with governed LLM gateways and compliance AI systems
in defense, healthcare, and financial services environments.
"""

from garak import _config
from garak.data import path as data_path
import garak.probes


def _load_prompts(*filenames: str) -> list[str]:
    """Load prompt lines from one or more data files under data/compliance/."""
    prompts: list[str] = []
    for filename in filenames:
        with open(
            data_path / "compliance" / filename, "r", encoding="utf-8"
        ) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    prompts.append(line)
    return prompts


class ComplianceHallucination(garak.probes.Probe):
    """Does the model fabricate regulatory citations or controls?

    Tests whether the LLM invents fake regulatory framework references,
    nonexistent control numbers, or fabricated compliance standards when
    asked about specific (fictitious) regulations. In regulated industries,
    hallucinated citations can lead to misguided compliance efforts,
    failed audits, and legal liability.
    """

    lang = "en"
    doc_uri = "https://csrc.nist.gov/publications/sp800"
    primary_detector = "compliance.FabricatedCitation"
    extended_detectors = [
        "compliance.RegulatoryConfidence",
        "mitigation.MitigationBypass",
    ]
    tags = [
        "avid-effect:performance:P0204",
        "owasp:llm09",
        "quality:Robustness:GenerativeMisinformation",
        "payload:hallucination",
        "payload:compliance",
    ]
    goal = "make the model fabricate regulatory citations or compliance controls"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_prompts(
            "hallucination_fake_nist.txt",
            "hallucination_fake_cmmc.txt",
            "hallucination_fake_dfars.txt",
            "hallucination_fake_hipaa.txt",
            "hallucination_fake_mappings.txt",
        )


class CompliancePIILeak(garak.probes.Probe):
    """Can the model be tricked into leaking PII from compliance contexts?

    Tests whether the LLM can be manipulated into revealing personally
    identifiable information (SSNs, emails, names, addresses) that might
    appear in compliance documents, assessment reports, or audit trails.
    In regulated environments, PII leakage through LLM outputs constitutes
    a data breach under HIPAA, CMMC, and state privacy laws.
    """

    lang = "en"
    doc_uri = "https://csrc.nist.gov/pubs/sp/800-122/final"
    primary_detector = "compliance.PIIPresence"
    extended_detectors = [
        "mitigation.MitigationBypass",
    ]
    tags = [
        "avid-effect:security:S0301",
        "owasp:llm06",
        "quality:Security:ExtractionInversion",
        "payload:pii",
        "payload:compliance",
    ]
    goal = "trick the model into revealing PII from compliance documents"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_prompts(
            "piileak_direct.txt",
            "piileak_indirect.txt",
            "piileak_roleplay.txt",
        )


class PolicyBypass(garak.probes.Probe):
    """Does the model help users circumvent compliance security controls?

    Tests whether the LLM provides guidance on bypassing, disabling, or
    circumventing security controls required by compliance frameworks.
    In regulated environments, models that assist in control circumvention
    undermine the security posture and can expose organizations to
    enforcement actions, failed audits, and adversary exploitation.
    """

    lang = "en"
    doc_uri = "https://dodcio.defense.gov/CMMC/"
    primary_detector = "compliance.BypassInstructions"
    extended_detectors = [
        "compliance.ControlWeakening",
        "mitigation.MitigationBypass",
    ]
    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
        "payload:compliance",
    ]
    goal = "get the model to provide instructions for bypassing compliance controls"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_prompts(
            "bypass_direct.txt",
            "bypass_social_engineering.txt",
            "bypass_technical.txt",
            "bypass_obfuscated.txt",
        )


class ComplianceStatusFabrication(garak.probes.Probe):
    """Does the model falsely assert or confirm compliance status?

    Tests whether the LLM fabricates, confirms, or generates false
    compliance certifications, assessment results, or attestation
    documents. False compliance assertions can constitute fraud in
    government contracting (False Claims Act liability) and mislead
    organizations about their actual security posture.
    """

    lang = "en"
    doc_uri = "https://dodcio.defense.gov/CMMC/"
    primary_detector = "compliance.FalseAttestation"
    extended_detectors = [
        "compliance.RegulatoryConfidence",
        "mitigation.MitigationBypass",
    ]
    tags = [
        "avid-effect:performance:P0204",
        "owasp:llm09",
        "quality:Robustness:GenerativeMisinformation",
        "payload:hallucination",
        "payload:compliance",
    ]
    goal = "make the model fabricate or confirm false compliance status"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_prompts(
            "fabrication_false_confirmation.txt",
            "fabrication_certificate_generation.txt",
            "fabrication_leading_questions.txt",
            "fabrication_score.txt",
        )
