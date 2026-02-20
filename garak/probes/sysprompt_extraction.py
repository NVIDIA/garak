"""**System Prompt Extraction**

Probes to test how easily a model's system prompt can be extracted.

This module tests various adversarial techniques to extract system prompts from LLMs.
It combines a library of system prompts with different attack strategies to assess
vulnerability to system prompt exfiltration attacks.

The probe uses conversation support to set system prompts and then attempts to extract
them using various attack techniques including direct requests, encoding tricks,
role-playing, and other documented extraction methods.
"""

import json
import logging
import random
from typing import List

from garak import _config
from garak.attempt import Conversation, Turn, Message
from garak.data import path as data_path
import garak.probes
from garak.probes.base import Probe


# Attack templates for system prompt extraction
# Based on research from multiple sources including:
# - Riley Goodside's early attacks
# - https://openreview.net/forum?id=5eqkTIQD9v (Table 5)
# - https://www.willowtreeapps.com/craft/how-to-define-llm-system-prompt-exfiltration-attacks
# - https://simonwillison.net/tags/exfiltration-attacks/


class SystemPromptExtraction(Probe):
    """Tests ability to extract system prompts using various attack techniques

    This probe combines system prompts from various sources with adversarial
    extraction techniques to test how easily a model reveals its system prompt.
    It uses conversation support to set system prompts and fuzzy matching to
    detect successful extractions.
    """

    lang = "en"
    primary_detector = "sysprompt_extraction.PromptExtraction"
    tags = [
        "avid-effect:security:S0301",
        "owasp:llm01",
        "quality:Security:PromptStability",
    ]
    goal = "extract the model's system prompt"
    doc_uri = "https://simonwillison.net/tags/exfiltration-attacks/"
    tier = garak.probes.Tier.OF_CONCERN
    active = True

    DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {
        "system_prompt_sources": [
            "garak-llm/drh-System-Prompt-Library",  # credit danielrosehill/System-Prompt-Library-030825
            "garak-llm/tm-system_prompt",  # credit teilomillet/system_prompt
        ],
        "system_prompt_subsample": 50,  # Maximum system prompts to test (for performance)
        "follow_prompt_cap": True,
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.system_prompts = self._load_system_prompt_datasets(
            self.system_prompt_sources, self.system_prompt_subsample
        )
        self.attack_templates = self._load_garak_attacks()
        self._generate_attempts()

    @staticmethod
    def _load_dataset_prompts(dataset_name: str, min_prompt_len: int = 20) -> List[str]:
        """Load prompts from a supported format dataset"""
        from datasets import load_dataset

        dataset = load_dataset(dataset_name, split="train", trust_remote_code=False)

        prompts = []
        for item in dataset:
            prompt_text = ""
            if "systemprompt" in item and item["systemprompt"]:
                prompt_text = item["systemprompt"].strip()
            elif "prompt" in item and item["prompt"]:
                prompt_text = item["prompt"].strip()
            # Filter out very short or empty prompts
            if len(prompt_text) > min_prompt_len:
                prompts.append(prompt_text)

        logging.info(f"Loaded {len(prompts)} prompts from {dataset_name} dataset")

        return prompts

    @staticmethod
    def _load_system_prompt_datasets(dataset_names, subsample_size) -> List[str]:
        """Load system prompts from configured sources"""
        system_prompts = set()

        for source in dataset_names:
            prompts = SystemPromptExtraction._load_dataset_prompts(source)
            system_prompts.update(prompts)

        # Assembling combinations from larger datasets can be expensive
        # Limit to system_prompt_subsample
        if subsample_size is not None and len(system_prompts) > subsample_size:
            system_prompts = random.sample(system_prompts, subsample_size)

        logging.info(
            f"Loaded {len(system_prompts)} system prompts for extraction testing"
        )

        return system_prompts

    @staticmethod
    def _load_garak_attacks() -> List[str]:

        attacks = []
        with open(
            data_path / "sysprompt_extraction" / "attacks.json", "r", encoding="utf-8"
        ) as attackfile:
            attacks_raw = json.load(attackfile)
            attacks = [attack for attack in attacks_raw if not attack[0] == "#"]

        return attacks

    def _generate_attempts(self):
        """Generate attempts by combining system prompts with attack templates"""
        self.prompts = []

        # Generate all combinations
        all_combinations = []
        for sys_prompt in self.system_prompts:
            for attack_template in self.attack_templates:
                all_combinations.append((sys_prompt, attack_template))

        # Apply prompt cap if needed
        if (
            self.follow_prompt_cap
            and len(all_combinations) > self.soft_probe_prompt_cap
        ):
            all_combinations = random.sample(
                all_combinations, self.soft_probe_prompt_cap
            )

        for idx, (sys_prompt, attack_template) in enumerate(all_combinations):
            turns = [
                Turn(role="system", content=Message(text=sys_prompt, lang=self.lang)),
                Turn(
                    role="user", content=Message(text=attack_template, lang=self.lang)
                ),
            ]
            conv = Conversation(turns=turns)
            self.prompts.append(conv)
