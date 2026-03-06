"""**System Prompt Extraction**

Probes that attempt to extract a model's system prompt using adversarial
techniques including direct requests, encoding tricks, and role-playing.

System prompts are sourced from HuggingFace datasets and combined with
attack templates loaded from ``garak/data/sysprompt_extraction/attacks.json``.
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


class SystemPromptExtraction(Probe):
    """Attempt to extract system prompts using adversarial attack templates

    Combines system prompts from HuggingFace datasets with attack templates
    to test whether a model will reveal its system prompt under adversarial
    pressure. Uses conversation support to set the system prompt, then probes
    with various extraction techniques."""

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
        "system_prompt_subsample": 50,
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
        """Load prompts from a HuggingFace dataset with 'systemprompt' or 'prompt' column."""
        from datasets import load_dataset

        dataset = load_dataset(dataset_name, split="train", trust_remote_code=False)

        prompts = []
        for item in dataset:
            prompt_text = ""
            if "systemprompt" in item and item["systemprompt"]:
                prompt_text = item["systemprompt"].strip()
            elif "prompt" in item and item["prompt"]:
                prompt_text = item["prompt"].strip()
            if len(prompt_text) > min_prompt_len:
                prompts.append(prompt_text)

        logging.info("Loaded %d prompts from %s", len(prompts), dataset_name)
        return prompts

    @staticmethod
    def _load_system_prompt_datasets(dataset_names, subsample_size) -> List[str]:
        """Load and deduplicate system prompts from configured HuggingFace sources."""
        system_prompts = set()

        for source in dataset_names:
            try:
                prompts = SystemPromptExtraction._load_dataset_prompts(source)
                system_prompts.update(prompts)
            except (ModuleNotFoundError, ImportError) as e:
                logging.warning(
                    "Failed to load system prompt dataset %s: %s", source, e
                )
            except Exception as e:
                logging.warning(
                    "Error loading system prompt dataset %s: %s", source, e
                )

        if subsample_size is not None and len(system_prompts) > subsample_size:
            system_prompts = random.sample(list(system_prompts), subsample_size)

        logging.info("Using %d system prompts for extraction testing", len(system_prompts))
        return system_prompts

    @staticmethod
    def _load_garak_attacks() -> List[str]:
        """Load attack templates from data file, skipping comment lines."""
        with open(
            data_path / "sysprompt_extraction" / "attacks.json", "r", encoding="utf-8"
        ) as attackfile:
            attacks_raw = json.load(attackfile)
        return [attack for attack in attacks_raw if not attack[0] == "#"]

    def _generate_attempts(self):
        """Build Conversation prompts from all (system_prompt, attack) combinations."""
        self.prompts = []

        all_combinations = [
            (sp, at)
            for sp in self.system_prompts
            for at in self.attack_templates
        ]

        if (
            self.follow_prompt_cap
            and len(all_combinations) > self.soft_probe_prompt_cap
        ):
            all_combinations = random.sample(
                all_combinations, self.soft_probe_prompt_cap
            )

        for sys_prompt, attack_template in all_combinations:
            turns = [
                Turn(role="system", content=Message(text=sys_prompt, lang=self.lang)),
                Turn(
                    role="user", content=Message(text=attack_template, lang=self.lang)
                ),
            ]
            self.prompts.append(Conversation(turns=turns))
