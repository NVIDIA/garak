# Defense Posture Community Patterns (CP-1001 — CP-1006)

Six community patterns for assessing the **defense posture** of LLM system prompts. Each pattern targets a specific defense layer that production AI systems commonly lack.

## Context

garak probes for offensive failures: *does the model break?*

These patterns assess the complementary question: *how well is the system prompt hardened before probes are even run?*

A system with a hardening score of 15/15 may still fail behavioral probes — but a system scoring 0/15 is virtually guaranteed to fail. Defense posture assessment identifies the gap before expensive behavioral testing begins.

## Patterns

| ID | Name | OWASP | Gap Rate | Hardening |
|----|------|-------|----------|-----------|
| CP-1001 | Role Boundary Defense | LLM01 | 91.7% | +2 |
| CP-1002 | System Prompt Data Leakage | LLM01 | 20.7% | +3 |
| CP-1003 | Multi-Language Bypass Resistance | LLM01 | 34.7% | +3 |
| CP-1004 | Social Engineering Resistance | LLM01 | 46.3% | +2 |
| CP-1005 | Output Weaponization Defense | LLM02 | 75.2% | +2 |
| CP-1006 | Indirect Injection via External Data | LLM01 | 96.7% | +3 |

**Gap Rate** = percentage of production system prompts lacking this defense (n=121 leaked prompts).

**Total hardening score**: 0–15. Threshold for "adequately hardened": &ge; 10.

## Methodology

Defense pattern analysis of 121 leaked production system prompts from [jujumilk3/leaked-system-prompts](https://github.com/jujumilk3/leaked-system-prompts) — a curated, verified collection of system prompts extracted from ChatGPT, Claude, Grok, Perplexity, Cursor, v0, Copilot, Notion AI, and others.

- **Scanner**: [prompt-defense-audit](https://github.com/ppcvote/prompt-defense-audit) — deterministic regex, no LLM calls, <5ms per prompt
- **Dataset**: [jujumilk3/leaked-system-prompts](https://github.com/jujumilk3/leaked-system-prompts) (n=121)
- **Reproducibility**: Clone both repos and run the scan yourself

### Limitations

- Regex measures defense keyword presence, not behavioral resilience
- Leaked prompts may be outdated (some from 2023)
- Selection bias: prompts that are easier to leak may be less well-defended
- n=121 is sufficient for directional findings, not precise confidence intervals

## Each Pattern Contains

```
probe:               Attack prompts with metadata
static_indicators:   Regex patterns for <1ms static scoring
behavioral:          Pass/fail criteria for model inference scoring
calibration:         Hardening score + expected false-refusal delta
empirical:           Real defense gap data with sample size
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
