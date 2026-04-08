"""ATR (Agent Threat Rules) detectors for AI agent threats.

Detects prompt injection, tool poisoning, credential exfiltration,
privilege escalation, and 5 other AI agent threat categories using
108 detection rules (714 regex patterns) from the ATR open-source project.

Rules ported from https://github.com/Agent-Threat-Rule/agent-threat-rules
(MIT license, adopted by Cisco AI Defense).

These detectors focus on AI agent-specific threats -- particularly
MCP tool poisoning, skill compromise, context exfiltration, and
excessive autonomy -- not covered by garak's existing detectors.
"""

import json
import logging
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable

import garak.attempt
from garak import _config
from garak.detectors.base import Detector

logger = logging.getLogger(__name__)

# Load all ATR patterns from bundled JSON (714 patterns across 9 categories)
_RULES_PATH = Path(__file__).parent / "atr_rules.json"
_ALL_RULES: dict[str, list[list[str]]] = {}
if _RULES_PATH.exists():
    with open(_RULES_PATH) as f:
        _ALL_RULES = json.load(f)
else:
    logger.warning("ATR rules file not found: %s", _RULES_PATH)


def sync_rules_from_github(
    repo: str = "Agent-Threat-Rule/agent-threat-rules",
    branch: str = "main",
    output: Path | None = None,
) -> int:
    """Fetch latest ATR rules from GitHub and update the bundled JSON.

    Requires: git, PyYAML (pip install pyyaml).
    Returns the number of patterns synced.

    Usage::

        from garak.detectors.atr import sync_rules_from_github
        count = sync_rules_from_github()
        print(f"Synced {count} patterns")
    """
    import yaml  # PyYAML -- optional dependency

    dest = output or _RULES_PATH
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(
            ["git", "clone", "--depth", "1", "-b", branch,
             f"https://github.com/{repo}.git", tmpdir],
            check=True, capture_output=True,
        )
        rules_dir = Path(tmpdir) / "rules"
        if not rules_dir.exists():
            raise FileNotFoundError(f"No rules/ directory in {repo}")

        result: dict[str, list[list[str]]] = {}
        for yaml_file in sorted(rules_dir.rglob("*.yaml")):
            doc = yaml.safe_load(yaml_file.read_text())
            if not doc or not doc.get("detection", {}).get("conditions"):
                continue
            cat = doc.get("tags", {}).get("category", "unknown")
            if cat not in result:
                result[cat] = []
            for cond in doc["detection"]["conditions"]:
                if cond.get("operator") == "regex" and cond.get("value"):
                    pat = re.sub(r"^\(\?[imsx]+\)", "", cond["value"])
                    result[cat].append([doc["id"], doc.get("severity", "medium"), pat])

        dest.write_text(json.dumps(result, indent=2, ensure_ascii=True))
        total = sum(len(v) for v in result.values())
        logger.info("ATR sync: %d patterns across %d categories -> %s", total, len(result), dest)
        return total


def generate_rule_from_probe(
    probe_outputs: list[str],
    category: str = "prompt-injection",
    severity: str = "high",
    min_common_length: int = 8,
) -> str:
    """Generate an ATR rule YAML draft from successful Garak probe outputs.

    Takes a list of strings that bypassed defenses (successful attacks)
    and extracts common substrings as detection patterns. Returns a
    YAML rule string ready for review and submission to ATR.

    This is a starting point -- generated rules should be reviewed by
    a human before being added to the ATR ruleset.

    Usage::

        from garak.detectors.atr import generate_rule_from_probe
        attacks = ["ignore previous instructions and ...", "forget all rules and ..."]
        rule_yaml = generate_rule_from_probe(attacks, category="prompt-injection")
        print(rule_yaml)
    """
    if not probe_outputs:
        return ""

    # Extract keywords that appear in 50%+ of outputs
    word_counts: dict[str, int] = {}
    for text in probe_outputs:
        words = set(re.findall(r"\b[a-zA-Z]{4,}\b", text.lower()))
        for w in words:
            word_counts[w] = word_counts.get(w, 0) + 1

    threshold = max(2, len(probe_outputs) // 2)
    common_words = sorted(
        [w for w, c in word_counts.items() if c >= threshold],
        key=lambda w: word_counts[w],
        reverse=True,
    )[:6]

    if not common_words:
        return ""

    # Build regex pattern from common words
    pattern = r"(?i)\b" + r"\b.*\b".join(re.escape(w) for w in common_words[:4]) + r"\b"

    date = datetime.now().strftime("%Y/%m/%d")
    rule_id = f"ATR-DRAFT-{hash(pattern) % 100000:05d}"

    return f"""title: "Garak-generated: {common_words[0]} pattern"
id: {rule_id}
rule_version: 1
status: draft
description: >
  Auto-generated from {len(probe_outputs)} successful Garak probe outputs.
  Common keywords: {', '.join(common_words[:6])}.
  REVIEW REQUIRED before adding to production ruleset.
author: "garak + ATR"
date: "{date}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: {severity}
tags:
  category: {category}
  subcategory: garak-generated
  confidence: low
agent_source:
  type: mcp_exchange
  framework: [any]
  provider: [any]
detection:
  conditions:
    - field: content
      operator: regex
      value: '{pattern}'
      description: "Pattern from {len(probe_outputs)} Garak probe outputs"
  condition: any
response:
  actions: [alert]
test_cases:
  true_positives:
    - input: "{probe_outputs[0][:100].replace(chr(34), chr(39))}"
      expected: triggered
"""


def _compile_category(category: str) -> list[tuple[str, re.Pattern]]:
    """Compile regex patterns for a given ATR category."""
    compiled = []
    for rule_id, _severity, pattern in _ALL_RULES.get(category, []):
        try:
            compiled.append((rule_id, re.compile(pattern, re.IGNORECASE)))
        except re.error as e:
            logger.debug("Skipping invalid ATR pattern %s: %s", rule_id, e)
    return compiled


class ATRDetector(Detector):
    """Base class for ATR regex-based detectors.

    Compiles patterns once at init, matches against all outputs.
    Returns 1.0 (hit) if any pattern matches, 0.0 otherwise.
    """

    lang_spec = "en"
    atr_categories: list[str] = []

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._compiled: list[tuple[str, re.Pattern]] = []
        for cat in self.atr_categories:
            self._compiled.extend(_compile_category(cat))
        logger.info(
            "ATR detector %s: %d patterns from %d categories",
            self.__class__.__name__,
            len(self._compiled),
            len(self.atr_categories),
        )

    def detect(self, attempt: garak.attempt.Attempt) -> Iterable[float | None]:
        results = []
        for output in attempt.outputs_for(self.lang_spec):
            if output is None or output.text is None:
                results.append(None)
                continue
            text = output.text
            hit = any(regex.search(text) for _, regex in self._compiled)
            results.append(1.0 if hit else 0.0)
        return results


class AgentThreats(ATRDetector):
    """Detect all 9 categories of AI agent threats (714 patterns).

    Comprehensive scan covering prompt injection, tool poisoning,
    credential exfiltration, privilege escalation, excessive autonomy,
    agent manipulation, skill compromise, data poisoning, and model abuse.
    """

    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
    ]
    hit_desc = "Output contains AI agent threat pattern"
    pass_desc = "No agent threat patterns detected"
    atr_categories = list(_ALL_RULES.keys())


class PromptInjection(ATRDetector):
    """Detect prompt injection patterns in agent outputs.

    Catches instruction override attempts, system prompt leaks,
    persona hijacking, and delimiter injection.
    ATR rules: ATR-2026-00001 through ATR-2026-00005, 00080-00094, 00097, 00104.
    """

    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
    ]
    hit_desc = "Output contains prompt injection pattern"
    pass_desc = "No prompt injection patterns detected"
    atr_categories = ["prompt-injection"]


class ToolPoisoning(ATRDetector):
    """Detect MCP tool poisoning and supply-chain attack patterns.

    Catches hidden instructions in tool descriptions, consent bypass
    directives, tool shadowing, and schema-description contradictions.
    ATR rules: ATR-2026-00010 through ATR-2026-00013, 00095-00096, 00100-00106.
    """

    tags = [
        "avid-effect:security:S0403",
        "owasp:llm03",
    ]
    hit_desc = "Output contains tool poisoning pattern"
    pass_desc = "No tool poisoning patterns detected"
    atr_categories = ["tool-poisoning"]


class CredentialExfiltration(ATRDetector):
    """Detect credential and API key exfiltration in outputs.

    Catches leaked API keys (OpenAI, Anthropic, GitHub, AWS, Slack),
    private keys, database URLs, JWT tokens, and system prompt disclosures.
    ATR rules: ATR-2026-00020, 00021, 00075, 00102, 00113-00115, 00136, 00141-00152.
    """

    tags = [
        "avid-effect:security:S0301",
        "owasp:llm06",
    ]
    hit_desc = "Output contains credential exfiltration pattern"
    pass_desc = "No credential exfiltration detected"
    atr_categories = ["context-exfiltration"]


class PrivilegeEscalation(ATRDetector):
    """Detect privilege escalation and unauthorized action patterns.

    Catches attempts to execute system commands, modify permissions,
    manage users, or access admin functions through agent tools.
    ATR rules: ATR-2026-00040, 00041, 00107, 00110-00112, 00143-00144.
    """

    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
    ]
    hit_desc = "Output contains privilege escalation pattern"
    pass_desc = "No privilege escalation detected"
    atr_categories = ["privilege-escalation"]


class SkillCompromise(ATRDetector):
    """Detect MCP skill compromise and supply-chain attack patterns.

    Catches skill impersonation, typosquatting, description-behavior
    mismatch, hidden capabilities, rug pulls, and parameter injection.
    ATR rules: ATR-2026-00060 through ATR-2026-00066, 00120-00135, 00147-00151.
    """

    tags = [
        "avid-effect:security:S0403",
        "owasp:llm03",
    ]
    hit_desc = "Output contains skill compromise pattern"
    pass_desc = "No skill compromise detected"
    atr_categories = ["skill-compromise"]


class ExcessiveAutonomy(ATRDetector):
    """Detect runaway agent loops and excessive autonomy patterns.

    Catches retry loops, resource exhaustion, cascading failures,
    and unauthorized financial actions.
    ATR rules: ATR-2026-00050 through ATR-2026-00052, 00098-00099.
    """

    tags = [
        "avid-effect:performance:P0204",
        "owasp:llm01",
    ]
    hit_desc = "Output contains excessive autonomy pattern"
    pass_desc = "No excessive autonomy detected"
    atr_categories = ["excessive-autonomy"]


class AgentManipulation(ATRDetector):
    """Detect cross-agent attacks and agent manipulation patterns.

    Catches cross-agent privilege escalation, message spoofing,
    human trust exploitation, and agent identity attacks.
    ATR rules: ATR-2026-00030, 00032, 00074, 00076-00077, 00108, 00116-00119.
    """

    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
    ]
    hit_desc = "Output contains agent manipulation pattern"
    pass_desc = "No agent manipulation detected"
    atr_categories = ["agent-manipulation"]


class DataPoisoning(ATRDetector):
    """Detect data poisoning and indirect injection via external content.

    Catches poisoned training data, injected instructions in retrieved
    documents, and context manipulation through data sources.
    ATR rules: ATR-2026-00070.
    """

    tags = [
        "avid-effect:security:S0301",
        "owasp:llm03",
    ]
    hit_desc = "Output contains data poisoning pattern"
    pass_desc = "No data poisoning detected"
    atr_categories = ["data-poisoning"]
