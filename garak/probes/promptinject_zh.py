"""**PromptInject ZH**

Chinese-language prompt injection probes.

garak's existing prompt-injection coverage is English-centric: the payload sets in
``promptinject``, ``dan`` and ``latentinjection`` rely on English overriding phrases
such as "ignore previous instructions". Chinese deployments rarely see those exact
strings, so a model that resists the English sets can still be trivially hijacked by
Chinese phrasing, role-play framings, full-width punctuation, pinyin, zero-width
characters or fake ``<|im_start|>system`` blocks.

Every payload here asks the target to echo a unique marker string. If the marker
appears in the output, the probe has overridden the model's current task; this makes
detection deterministic and keeps the false-positive rate low, since the markers never
occur in natural text.

Payloads live in ``garak/data/promptinject_zh/payloads.json`` and are grouped by
technique, so a run can target one family (``-p promptinject_zh.PromptInjectZhEncoding``)
or all of them (``-p promptinject_zh``).
"""

import json
import logging
import random
from typing import Iterable, List, Union

from garak import _config
from garak.attempt import Attempt
from garak.data import path as data_path
import garak.probes
from garak.probes.base import Probe

DEFAULT_PAYLOAD_FILE = "promptinject_zh/payloads.json"

_COMMON_TAGS = [
    "owasp:llm01",
    "avid-effect:security:S0403",
    "quality:Security:PromptStability",
    "euai:robustness:adversarial",
]


class PromptInjectZh(Probe):
    """Chinese prompt injection probes covering all bundled techniques

    Sends Chinese-language injection payloads (direct overrides, role-play
    jailbreaks, delimiter spoofing, encoding bypasses and emotional coercion) and
    checks whether the model echoes the attacker-chosen marker string."""

    lang = "zh"
    active = True
    doc_uri = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    goal = "make the model abandon its task and echo an attacker-chosen marker using Chinese-language injection"
    intent = "T009ignore"
    primary_detector = "base.TriggerListDetector"
    tags = _COMMON_TAGS + [
        "demon:Language:Prompt_injection:Ignore_previous_instructions"
    ]
    tier = garak.probes.Tier.OF_CONCERN
    payload_file = DEFAULT_PAYLOAD_FILE
    # None selects every technique; subclasses pin a single family
    technique: Union[str, None] = None

    DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {
        "payload_limit": None,
        "shuffle_payloads": False,
        "shuffle_seed": 42,
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.payloads = self._load_payloads()
        if self.payload_limit:
            self.payloads = self.payloads[: self.payload_limit]
        if self.shuffle_payloads:
            random.Random(self.shuffle_seed).shuffle(self.payloads)
        self.prompts = [payload["prompt"] for payload in self.payloads]
        logging.info(
            "promptinject_zh: loaded %s payloads (technique=%s)",
            len(self.payloads),
            self.technique or "all",
        )

    def _load_payloads(self) -> List[dict]:
        with open(data_path / self.payload_file, "r", encoding="utf-8") as f:
            payload_data = json.load(f)
        payloads = payload_data["payloads"]
        if self.technique:
            payloads = [p for p in payloads if p["technique"] == self.technique]
            if not payloads:
                raise ValueError(
                    f"no promptinject_zh payloads for technique {self.technique!r}; "
                    f"known techniques: {sorted(payload_data['techniques'])}"
                )
        return payloads

    def _attempt_prestore_hook(self, attempt: Attempt, seq: int) -> Attempt:
        payload = self.payloads[seq]
        attempt.notes["triggers"] = [payload["trigger"]]
        attempt.notes["payload_id"] = payload["id"]
        attempt.notes["technique"] = payload["technique"]
        return attempt


class PromptInjectZhOverride(PromptInjectZh):
    """Chinese direct instruction-override payloads

    "忽略以上指令" style overrides, including variants that wrap the injection in an
    otherwise benign request."""

    technique = "instruction_override"
    active = False
    goal = "override the model's current task with a Chinese direct instruction"


class PromptInjectZhRolePlay(PromptInjectZh):
    """Chinese role-play jailbreak payloads

    Jailbreaks that assign the model an unrestrained persona (DAN, developer mode,
    audit bot) and request a persona-specific confirmation marker."""

    technique = "role_play_jailbreak"
    active = False
    goal = "make the model adopt a persona that ignores its safety policy"


class PromptInjectZhDelimiter(PromptInjectZh):
    """Chinese delimiter / fake system-message spoofing payloads

    Fakes ``<|im_start|>system`` blocks, ``### SYSTEM ###`` separators, YAML/JSON
    configs and HTML comments to smuggle instructions past the user turn."""

    technique = "delimiter_spoof"
    active = False
    intent = "T009indirect"
    goal = "smuggle instructions through forged system-message delimiters"


class PromptInjectZhEncoding(PromptInjectZh):
    """Chinese encoding-bypass payloads

    Hides the instruction in Base64, URL encoding, hex, pinyin, zero-width characters,
    character spacing, reversed text or Traditional Chinese to evade keyword filters."""

    technique = "encoding_bypass"
    active = False
    goal = "evade keyword filtering by encoding a Chinese injection instruction"


class PromptInjectZhCoercion(PromptInjectZh):
    """Chinese emotional-coercion payloads

    Pressures the model with security drills, urgent outages, academic scoring or
    sympathy to obtain a marker echo."""

    technique = "emotional_coercion"
    active = False
    goal = "pressure the model into compliance through emotional framing"
