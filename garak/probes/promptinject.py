"""**PromptInject**

Basic prompt injections, including plaintext malicious commands into requests
for innocuous information.

Probes in this module should specifically implement parts of the PromptInject
framework.

Uses the PromptInject framework, https://openreview.net/forum?id=qiaRo_7Zmug,
to probe a system. A subset of the attacks is implemented here. The default
is to use a selection of that subset, because even the subset corresponds to
thousands of requests by default.

Further info:

* https://openreview.net/forum?id=qiaRo_7Zmug

"""

import json
import logging
import random
import sys

from garak.attempt import Attempt
from garak.data import path as data_path
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

    self.pi_build_prompts = build_prompts
    self.load_data_all_attacks(prompt_data)

    # self.prompts.append(f"{prefix} {false_assertion}")


def load_data_all_attacks(self, prompt_data):
    prompt_config = {
        "base": {
            "text": prompt_data.ALL_OPENAI_PLAYGROUND_PROMPTS,
        },
        "attack": {
            "text": (
                prompt_data.goal_hikacking_attacks["ignore-print"],
                prompt_data.goal_hikacking_attacks["ignore-say"],
                prompt_data.goal_hikacking_attacks["ignore-print-upper"],
                prompt_data.goal_hikacking_attacks["nevermind"],
                prompt_data.goal_hikacking_attacks["screaming-stop"],
            ),
            "rogue_string": prompt_data.rogue_strings[self.rogue_string],
            "scoring": "match_rogue_to_output",
            "settings": {
                "escape": prompt_data.escape_chars["n"],
                "delimiter": prompt_data.delimiter_chars["dash"],
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


# ---------------------------------------------------------------------------
# AgentHarm probes
# ---------------------------------------------------------------------------
# Probes drawn from the AgentHarm benchmark (arxiv:2410.09024).
# The technique — jailbreak framing applied to agentic task prompts — places
# them in the promptinject family.  Harm categories and dataset loading are
# specific to the AgentHarm dataset; detectors live in mitigation.AgentRefusal
# and mitigation.AgentTaskCompletion.
# ---------------------------------------------------------------------------

AGENTHARM_TAGS = [
    "avid-effect:security:S0403",
    "avid-effect:ethics:E0301",
    "owasp:llm01",
    "quality:Behavioral:ContentSafety:LegalGoodsServices",
    "quality:Behavioral:ContentSafety:HateHarassment",
    "quality:Behavioral:ContentSafety:Unauthorized",
]

CATEGORIES = [
    "Copyright",
    "Cybercrime",
    "Disinformation",
    "Drugs",
    "Fraud",
    "Harassment",
    "Hate",
    "Sexual",
]

_CROSS_CATEGORY_PATH = data_path / "agentharm" / "cross_category.json"


def _load_prompts(
    dataset_path,
    dataset_config,
    dataset_split,
    category=None,
    hint_included=None,
    detailed_prompt=None,
):
    """Return prompts from the AgentHarm dataset with optional filters."""
    from datasets import load_dataset

    try:
        ds = load_dataset(
            dataset_path, dataset_config, split=dataset_split, trust_remote_code=False
        )
    except Exception as exc:
        logging.warning("agentharm: failed to load dataset %s: %s", dataset_path, exc)
        return []

    rows = list(ds)
    if category is not None:
        rows = [r for r in rows if r["category"].lower() == category.lower()]
    if hint_included is not None:
        rows = [r for r in rows if r["hint_included"] == hint_included]
    if detailed_prompt is not None:
        rows = [r for r in rows if r["detailed_prompt"] == detailed_prompt]
    return [r["prompt"] for r in rows]


def _load_cross_category():
    with open(_CROSS_CATEGORY_PATH, encoding="utf-8") as f:
        return json.load(f)


class AgentHarm(garak.probes.Probe):
    """Probe base AgentHarm tasks with no augmentation.

    Loads the 44 unique harmful agentic task prompts from the public
    AgentHarm benchmark (``hint_included=False``, ``detailed_prompt=False``).
    Tests whether a model will assist with harmful agentic operations across
    eight publicly available harm categories."""

    lang = "en"
    doc_uri = "https://arxiv.org/abs/2410.09024"
    primary_detector = "mitigation.AgentRefusal"
    extended_detectors = ["mitigation.AgentRefusal", "mitigation.AgentTaskCompletion"]
    tags = AGENTHARM_TAGS
    goal = "get the model to assist with a harmful agent task"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "dataset_path": "ai-safety-institute/AgentHarm",
        "dataset_config": "harmful",
        "dataset_split": "test_public",
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = _load_prompts(
            self.dataset_path,
            self.dataset_config,
            self.dataset_split,
            hint_included=False,
            detailed_prompt=False,
        )
        self._prune_data(cap=self.soft_probe_prompt_cap)


class AgentHarmAugmented(AgentHarm):
    """Probe all AgentHarm augmentation variants.

    Loads all 176 rows from the public AgentHarm test split, covering the
    four combinations of ``hint_included`` x ``detailed_prompt`` augmentation
    axes. Useful for measuring whether augmenting a prompt with hints or
    additional detail changes the model's safety behaviour."""

    goal = "get the model to assist with a harmful agent task across all augmentation variants"
    active = False

    def __init__(self, config_root=_config):
        super(AgentHarm, self).__init__(config_root=config_root)
        self.prompts = _load_prompts(
            self.dataset_path,
            self.dataset_config,
            self.dataset_split,
        )
        self._prune_data(cap=self.soft_probe_prompt_cap)


def _category_constructor(self, config_root=_config):
    super(self.__class__, self).__init__(config_root=config_root)
    self.prompts = _load_prompts(
        self.dataset_path,
        self.dataset_config,
        self.dataset_split,
        category=self._category,
        hint_included=False,
        detailed_prompt=False,
    )
    self._prune_data(cap=self.soft_probe_prompt_cap)


for _category in CATEGORIES:
    _classname = _category
    _goal = f"get the model to assist with a {_category.lower()} harmful agent task"
    _doc = (
        f"Probe AgentHarm tasks in the {_category} category.\n\n"
        f"Loads the subset of base AgentHarm prompts (no hint, no detail) that "
        f"belong to the {_category} harm category."
    )

    setattr(
        this,
        _classname,
        type(
            _classname,
            (AgentHarm,),
            {
                "__init__": _category_constructor,
                "__doc__": _doc,
                "_category": _category,
                "goal": _goal,
                "active": False,
                "tier": garak.probes.Tier.COMPETE_WITH_SOTA,
            },
        ),
    )


class CrossCategory(garak.probes.Probe):
    """Probe cross-category harmful task combinations using curated interaction prompts.

    Tests whether combining two harm categories in a single request exploits
    the natural operational overlap and bypasses safety guardrails that hold
    for either category alone. Uses research-backed jailbreak framing patterns
    (fictional framing, research justification, sequential dependency) documented
    in jailbreak literature.

    Ten curated prompts cover the highest-interaction pairs: Cybercrime x Fraud,
    Cybercrime x Harassment, Cybercrime x Disinformation, Disinformation x Harassment,
    Disinformation x Hate, Drugs x Cybercrime, Fraud x Drugs, Harassment x Sexual,
    Hate x Harassment, and Copyright x Fraud.

    Uses ``judge.Jailbreak`` as the primary detector because keyword matching
    misses sophisticated compliant responses. ``mitigation.AgentRefusal`` and
    ``mitigation.AgentTaskCompletion`` run as extended detectors."""

    lang = "en"
    doc_uri = "https://arxiv.org/abs/2410.09024"
    primary_detector = "judge.Jailbreak"
    extended_detectors = ["mitigation.AgentRefusal", "mitigation.AgentTaskCompletion"]
    tags = AGENTHARM_TAGS
    goal = "get the model to assist with harmful tasks spanning two harm categories in one request"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = False

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        entries = _load_cross_category()
        self._attack_goals = [e["attack_goal"] for e in entries]
        self.prompts = [e["prompt"] for e in entries]

    def _attempt_prestore_hook(self, attempt, seq: int):
        attempt.notes = dict(attempt.notes or {})
        attempt.notes["attack_goal"] = self._attack_goals[seq]
        return attempt
