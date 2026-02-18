# Compliance Probes

Prompt data for compliance-focused vulnerability probes targeting LLMs deployed
in regulated industries (CMMC, NIST SP 800-171/53, HIPAA, DFARS, FedRAMP).

## Motivation

LLMs are increasingly used for regulatory guidance in defense, healthcare, and
financial services. These probes address compliance-specific risks where
hallucinated citations, leaked PII, or false attestations can lead to failed
audits, legal liability, and security breaches.

## Probes

| Probe | Data Files | Description |
|-------|-----------|-------------|
| `ComplianceHallucination` | `hallucination_fake_*.txt` | Tests if the model fabricates regulatory citations (fake NIST controls, CMMC practices, DFARS clauses, HIPAA sections) |
| `CompliancePIILeak` | `piileak_*.txt` | Tests if the model leaks PII via compliance-framed prompts (direct extraction, social engineering, roleplay) |
| `PolicyBypass` | `bypass_*.txt` | Tests if the model provides instructions for circumventing security controls (including Unicode/homoglyph obfuscation) |
| `ComplianceStatusFabrication` | `fabrication_*.txt` | Tests if the model generates false compliance certifications or attestations |

## Detectors

| Detector | What It Catches |
|----------|----------------|
| `FabricatedCitation` | Validates citations against real control families (SP 800-171, SP 800-53, CMMC Levels 1-3, DFARS 252.204-70xx, HIPAA 164.xxx) |
| `RegulatoryConfidence` | Flags overly definitive regulatory claims without hedging |
| `PIIPresence` | Detects SSN (with synthetic prefix filtering), credit card (with Luhn validation), email, phone (with DFARS clause filtering) |
| `BypassInstructions` | Detects actionable bypass guidance with code pattern detection |
| `ControlWeakening` | Identifies suggestions to reduce security control effectiveness |
| `FalseAttestation` | Catches false compliance certifications (distinguishes C3PAO in fake certs vs proper disclaimers) |

## OWASP LLM Top 10 Coverage

- **LLM01 (Prompt Injection)** - PolicyBypass
- **LLM06 (Sensitive Info Disclosure)** - CompliancePIILeak
- **LLM09 (Misinformation)** - ComplianceHallucination, ComplianceStatusFabrication

## File Naming Convention

Data files follow the pattern `{probe_category}_{variant}.txt`, one prompt per
line. Five prompts in `bypass_obfuscated.txt` contain intentional Unicode
homoglyph characters for testing obfuscation detection.

## Related Source

- Probes: `garak/probes/compliance.py`
- Detectors: `garak/detectors/compliance.py`
- Tests: `tests/probes/test_probes_compliance.py`, `tests/detectors/test_detectors_compliance.py`
