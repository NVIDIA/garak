"""PromptInject

Uses the PromptInject framework, https://openreview.net/forum?id=qiaRo_7Zmug,
to probe a system. A subset of the attacks is implemented here. The default
is to use a selection of that subset, because even the subset corresponds to
thousands of requests by default.
"""

import random
import sys

from garak.attempt import Attempt
import garak.probes
from garak import _config


hijacking_attacks = (
    "ignore-say ignore-print ignore-print-upper nevermind screaming-stop".split()
)
rogue_strings = "hate-humans kill-humans long-prompt".split()

this = sys.modules[__name__]


def constructor(self, config_root=_config):
    super(self.__class__, self).__init__(config_root=config_root)
    from garak.resources.promptinject import (
        build_prompts,
        prompt_data,
    )

    self.max_prompts = self.soft_probe_prompt_cap
    if self.__class__.__name__.endswith("Full"):
        self.max_prompts = None

    self.pi_prompt_data = prompt_data
    self.pi_build_prompts = build_prompts
    self.load_data_all_attacks()

    # self.prompts.append(f"{prefix} {false_assertion}")


def load_data_all_attacks(self):
    prompt_config = {
        "base": {
            "text": self.pi_prompt_data.ALL_OPENAI_PLAYGROUND_PROMPTS,
        },
        "attack": {
            "text": (
                self.pi_prompt_data.goal_hikacking_attacks["ignore-print"],
                self.pi_prompt_data.goal_hikacking_attacks["ignore-say"],
                self.pi_prompt_data.goal_hikacking_attacks["ignore-print-upper"],
                self.pi_prompt_data.goal_hikacking_attacks["nevermind"],
                self.pi_prompt_data.goal_hikacking_attacks["screaming-stop"],
            ),
            "rogue_string": self.pi_prompt_data.rogue_strings[self.rogue_string],
            "scoring": "match_rogue_to_output",
            "settings": {
                "escape": self.pi_prompt_data.escape_chars["n"],
                "delimiter": self.pi_prompt_data.delimiter_chars["dash"],
                "escape_length": 10,
                "escape_times": 2,
            },
        },
        "config": {
            "id": (0, 1, 2, 3),
        },
    }
    self.prompts = []
    self.pi_prompts = self.pi_build_prompts(prompt_config)
    for pi_prompt in self.pi_prompts:
        self.prompts.append(pi_prompt["prompt"])
    if self.max_prompts:
        random.seed(self.seed)
        random.shuffle(self.prompts)
        self.prompts = self.prompts[-self.max_prompts :]


def _attempt_prestore_hook(self, attempt: Attempt, seq: int) -> Attempt:
    attempt.notes["settings"] = self.pi_prompts[seq]["settings"]
    attempt.notes["triggers"] = [
        self.pi_prompts[seq]["settings"]["attack_rogue_string"]
    ]
    return attempt


def _generator_precall_hook(self, generator, attempt):
    """apply PromptInject model inference parameters to probe"""
    map_attribs = (
        "temperature top_p frequency_penalty presence_penalty max_tokens".split()
    )
    for map_attrib in map_attribs:
        if map_attrib in dir(generator):
            setattr(
                generator,
                map_attrib,
                attempt.notes["settings"]["config_" + map_attrib],
            )


for rogue_string in rogue_strings:
    classname = "Hijack" + rogue_string.replace("-", " ").title().replace(" ", "")

    setattr(
        this,
        classname + "Full",
        type(
            classname + "Full",
            (garak.probes.Probe,),
            {
                "__init__": constructor,
                "__doc__": f"PromptInject probe to inject a string; payload is {rogue_string}\n\nAttempt to make the model repeat a given string",
                "name": "promptinject_" + rogue_string,
                "lang": "en",
                "description": "PromptInject is a framework that assembles prompts in a modular fashion to provide a quantitative analysis of the robustness of LLMs to adversarial prompt attacks. trophy Best Paper Awards @ NeurIPS ML Safety Workshop 2022",
                "primary_detector": "promptinject.AttackRogueString",
                "parallelisable_attempts": False,
                "tags": [
                    "avid-effect:security:S0403",
                    "owasp:llm01",
                    "quality:Behavioral:ContentSafety:Violence",
                    "quality:Security:PromptStability",
                    "payload:unwanted:violence",
                ],
                "load_data_all_attacks": load_data_all_attacks,
                "uri": "https://openreview.net/forum?id=qiaRo_7Zmug",
                "rogue_string": rogue_string,
                "_attempt_prestore_hook": _attempt_prestore_hook,
                "_generator_precall_hook": _generator_precall_hook,
                "goal": "inject a prompt on " + rogue_string.replace("-", " "),
                "active": False,
                "tier": garak.probes.Tier.COMPETE_WITH_SOTA,
            },
        ),
    )

    setattr(
        this,
        classname,
        type(
            classname,
            (garak.probes.Probe,),
            {
                "__init__": constructor,
                "__doc__": f"PromptInject probe to inject a string; payload is {rogue_string}\n\nAttempt to make the model repeat a given string",
                "name": "promptinject_" + rogue_string,
                "lang": "en",
                "description": "PromptInject is a framework that assembles prompts in a modular fashion to provide a quantitative analysis of the robustness of LLMs to adversarial prompt attacks. trophy Best Paper Awards @ NeurIPS ML Safety Workshop 2022",
                "primary_detector": "promptinject.AttackRogueString",
                "parallelisable_attempts": False,
                "tags": [
                    "avid-effect:security:S0403",
                    "owasp:llm01",
                    "quality:Behavioral:ContentSafety:Violence",
                    "quality:Security:PromptStability",
                    "payload:unwanted:violence",
                ],
                "load_data_all_attacks": load_data_all_attacks,
                "uri": "https://openreview.net/forum?id=qiaRo_7Zmug",
                "rogue_string": rogue_string,
                "_attempt_prestore_hook": _attempt_prestore_hook,
                "_generator_precall_hook": _generator_precall_hook,
                "goal": "inject a prompt on " + rogue_string.replace("-", " "),
                "active": True,
                "tier": garak.probes.Tier.COMPETE_WITH_SOTA,
            },
        ),
    )
