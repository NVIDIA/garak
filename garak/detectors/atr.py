"""ATR (Agent Threat Rules) detectors for AI agent threats.

Detects prompt injection, tool poisoning, credential exfiltration,
privilege escalation, and 5 other AI agent threat categories using
113 detection rules (736 regex patterns) from the ATR open-source project.

Rules ported from https://github.com/Agent-Threat-Rule/agent-threat-rules
(MIT license, adopted by Cisco AI Defense).

These detectors focus on AI agent-specific threats -- particularly
MCP tool poisoning, skill compromise, context exfiltration, and
excessive autonomy -- not covered by garak's existing detectors.
"""

import json
import logging
import re
from typing import Iterable

import garak.attempt
from garak import _config
from garak.data import path as data_path
from garak.detectors.base import Detector

logger = logging.getLogger(__name__)

_RULES_FILENAME = "rules.json"


def _load_rules() -> dict[str, list[list[str]]]:
    """Load ATR rules from garak's data directory."""
    rules_path = data_path / __name__.split(".")[-1] / _RULES_FILENAME
    if not rules_path.exists():
        logger.warning("ATR rules file not found: %s", rules_path)
        return {}
    with open(rules_path, encoding="utf-8") as f:
        return json.load(f)


def _compile_category(
    rules: dict[str, list[list[str]]], category: str
) -> list[tuple[str, re.Pattern]]:
    """Compile regex patterns for a given ATR category."""
    compiled = []
    for rule_id, _severity, pattern in rules.get(category, []):
        try:
            compiled.append((rule_id, re.compile(pattern, re.IGNORECASE)))
        except re.error as e:
            logger.debug("Skipping invalid ATR pattern %s: %s", rule_id, e)
    return compiled


class ATRDetector(Detector):
    """Base class for ATR regex-based detectors.

    Loads rules from ``garak/data/atr/rules.json`` at init time. Users can
    override the bundled file by placing a custom ``rules.json`` under
    ``$XDG_DATA_HOME/garak/data/atr/rules.json``.

    Returns 1.0 (hit) if any pattern matches, 0.0 otherwise.
    """

    lang_spec = "en"
    atr_categories: list[str] = []

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        rules = _load_rules()
        self._compiled: list[tuple[str, re.Pattern]] = []
        for cat in self.atr_categories or list(rules.keys()):
            self._compiled.extend(_compile_category(rules, cat))
        logger.info(
            "ATR detector %s: %d patterns from %d categories",
            self.__class__.__name__,
            len(self._compiled),
            len(self.atr_categories) or len(rules),
        )

    def detect(self, attempt: garak.attempt.Attempt) -> Iterable[float | None]:
        results = []
        for output in attempt.outputs_for(self.lang_spec):
            if output is None or output.text is None:
                results.append(None)
                continue
            hit = any(regex.search(output.text) for _, regex in self._compiled)
            results.append(1.0 if hit else 0.0)
        return results


class AgentThreats(ATRDetector):
    """Detect all 9 categories of AI agent threats (736 patterns).

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
    # empty list = all categories loaded in __init__
    atr_categories = []


class PromptInjection(ATRDetector):
    """Detect prompt injection patterns in agent outputs.

    Catches instruction override attempts, system prompt leaks,
    persona hijacking, and delimiter injection.
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
    """

    tags = [
        "avid-effect:security:S0301",
        "owasp:llm03",
    ]
    hit_desc = "Output contains data poisoning pattern"
    pass_desc = "No data poisoning detected"
    atr_categories = ["data-poisoning"]
