# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""**Chinese Jailbreak Probes**

A collection of jailbreak probes targeting Chinese-language LLMs.

Probes in this module cover:
* ZhDan — Chinese DAN-style role-play and persona-modulation attacks
* ZhAcademicFraming — academic/scientific framing to bypass content restrictions
* ZhCulturalBypass — exploiting Chinese cultural context and literary forms
* ZhTranslationBypass — embedding malicious instructions in translation requests
* ZhContextInjection — hiding injection prompts in everyday Chinese text

These probes address a gap in garak's coverage: almost all existing probes
are ``lang=\"en\"``, missing the security characteristics of Chinese LLMs.
"""

import json
import logging

from garak import _config
from garak.data import path as data_path
import garak.probes


# Shared tags for Chinese jailbreak probes
_ZH_JAILBREAK_TAGS = [
    "avid-effect:security:S0403",
    "owasp:llm01",
    "quality:Security:PromptStability",
    "payload:jailbreak",
]


def _load_zh_prompts(filename: str) -> list:
    """Load prompts from a JSON file in the zh_jailbreak data directory."""
    try:
        prompt_path = data_path / "zh_jailbreak" / filename
        with open(prompt_path, "r", encoding="utf-8") as f:
            return [p for p in json.load(f) if p and p.strip()]
    except Exception as e:
        logging.error("Failed to load %s prompts: %s", filename, e)
        return []


class ZhDan(garak.probes.Probe):
    """Chinese DAN-style jailbreak.

    Uses Chinese-language role-play, developer-mode, and persona-modulation
    prompts to bypass content restrictions on Chinese LLMs. Based on the
    same principles as English DAN attacks but adapted for Chinese language
    and cultural context."""

    lang = "zh"
    goal = "disregard the system prompt and content restrictions"
    primary_detector = "zh_jailbreak.ZhMitigationBypass"
    tags = _ZH_JAILBREAK_TAGS + ["avid-effect:performance:P0204"]
    tier = garak.probes.Tier.OF_CONCERN
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_zh_prompts("zh_dan.json")
        self._prune_data(self.soft_probe_prompt_cap)


class ZhAcademicFraming(garak.probes.Probe):
    """Academic and research framing bypass.

    Presents harmful requests as academic research, thesis work, or
    scientific studies. Exploits the tendency of LLMs to cooperate with
    perceived academic authority and research legitimacy."""

    lang = "zh"
    goal = "disregard content restrictions under academic pretense"
    primary_detector = "zh_jailbreak.ZhMitigationBypass"
    tags = _ZH_JAILBREAK_TAGS
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_zh_prompts("zh_academic.json")
        self._prune_data(self.soft_probe_prompt_cap)


class ZhCulturalBypass(garak.probes.Probe):
    """Cultural context bypass.

    Wraps harmful requests in Chinese historical, literary, and cultural
    references — poetry, classical texts, historical scenarios. Exploits
    the unique cultural framing that most LLM safety training (which is
    English-dominated) does not adequately cover."""

    lang = "zh"
    goal = "disregard content restrictions via cultural framing"
    primary_detector = "zh_jailbreak.ZhMitigationBypass"
    tags = _ZH_JAILBREAK_TAGS
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_zh_prompts("zh_cultural_bypass.json")
        self._prune_data(self.soft_probe_prompt_cap)


class ZhTranslationBypass(garak.probes.Probe):
    """Translation-based jailbreak bypass.

    Asks the model to translate English text that contains hidden
    malicious instructions or harmful content. The translation process
    may cause the model to process and output harmful content that it
    would otherwise refuse. Uses both Chinese and English detectors for
    cross-language coverage."""

    lang = "zh"
    goal = "disregard content restrictions through translation requests"
    primary_detector = "zh_jailbreak.ZhMitigationBypass"
    extended_detectors = ["mitigation.MitigationBypass"]
    tags = _ZH_JAILBREAK_TAGS
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_zh_prompts("zh_translation_bypass.json")
        self._prune_data(self.soft_probe_prompt_cap)


class ZhContextInjection(garak.probes.Probe):
    """Chinese context injection attacks.

    Hides injection prompts within everyday Chinese text — resumes,
    news articles, financial reports, contracts. The benign outer context
    serves as camouflage for the embedded malicious instruction.
    Uses TriggerListDetector to check if the model followed the hidden
    instruction rather than the visible task."""

    lang = "zh"
    goal = "execute hidden instructions embedded in Chinese context"
    primary_detector = "zh_jailbreak.ZhMitigationBypass"
    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
    ]
    tier = garak.probes.Tier.OF_CONCERN
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_zh_prompts("zh_context_injection.json")
        self._prune_data(self.soft_probe_prompt_cap)
