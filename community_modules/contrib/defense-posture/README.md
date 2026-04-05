# Defense Posture Community Patterns (CP-1001 — CP-1006)

Six community patterns for assessing the **defense posture** of LLM system prompts. Each pattern targets a specific defense layer that production AI applications commonly lack.

## Context

garak probes for offensive failures: *does the model break?*

These patterns assess the complementary question: *how well is the system prompt hardened before probes are even run?*

A system with a hardening score of 15/15 may still fail behavioral probes — but a system scoring 0/15 is virtually guaranteed to fail. Defense posture assessment identifies the gap before expensive behavioral testing begins.

## Patterns

| ID | Name | OWASP | Gap Rate | Hardening |
|----|------|-------|----------|-----------|
| CP-1001 | Role Boundary Defense | LLM01 | 41% | +2 |
| CP-1002 | System Prompt Data Leakage | LLM01 | 59% | +3 |
| CP-1003 | Multi-Language Bypass Resistance | LLM01 | 72% | +3 |
| CP-1004 | Social Engineering Resistance | LLM01 | 82% | +2 |
| CP-1005 | Output Weaponization Defense | LLM02 | 66% | +2 |
| CP-1006 | Indirect Injection via External Data | LLM01 | 96% | +3 |

**Gap Rate** = percentage of production AI applications lacking this defense (n=721).

**Total hardening score**: 0–15. Threshold for "adequately hardened": &ge; 10.

## Methodology

Empirical data from scanning 721 URLs cited by OpenAI's `web_search` tool across 155 queries spanning 5 domains (technology, local services, recommendations, e-commerce, health).

- **Dataset**: [doi:10.5281/zenodo.19410475](https://doi.org/10.5281/zenodo.19410475)
- **Scanner**: [UltraProbe](https://ultralab.tw/en/probe) — deterministic regex, no LLM calls, <50ms
- **Open source**: [ultralab-scanners](https://github.com/ppcvote/ultralab-scanners)

## Each Pattern Contains

```
probe:               Attack prompts with metadata
static_indicators:   Regex patterns for <1ms static scoring
behavioral:          Pass/fail criteria for model inference scoring
calibration:         Hardening score + expected false-refusal delta
empirical:           Real-world defense gap data with sample size
```

## Static + Behavioral Scoring

Each pattern supports two scoring modes that can run in one pass:

1. **Static** (`static_indicators`): Regex analysis of the system prompt text. Returns a hardening score contribution (integer). Runs in <1ms, zero cost.

2. **Behavioral** (`behavioral`): Sends probe prompts to the model and evaluates responses against pass/fail criteria. Returns 0.0 (defended) to 1.0 (compromised). Requires model inference.

Combined scoring enables a two-phase workflow:
- Phase 1: Static scan all system prompts (free, instant)
- Phase 2: Behavioral test only those below the hardening threshold (targeted, cost-efficient)

## Calibration

Each pattern includes `expected_false_refusal_delta` — the estimated increase in false refusal rate when the defense is present. This enables correlation between hardening score and over-refusal, which can be validated against the 25-test calibration corpus (per [#1666](https://github.com/NVIDIA/garak/issues/1666)).

## Schema

All patterns follow `schema_version: "1.0.0"`. See `index.yaml` for the collection manifest.

## Contributor

**MinYi Xie** ([@ppcvote](https://github.com/ppcvote)) — [Ultra Lab](https://ultralab.tw/en/)
