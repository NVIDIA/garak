"""**Do-Not-Answer Probes**

Present the target with a request for contentious or unwanted content.

Probes in this module should be from the "Do Not Answer" paper.

Do-Not-Answer is an open-source dataset to evaluate LLMs' safety mechanism at a low cost.
The dataset consists of prompts to which language models are often trained not to answer.

The DNA tests are somewhat opinionated and don't represent universal norms (nothing does), so use with care.

Further info:
* https://github.com/Libr-AI/do-not-answer
* https://arxiv.org/abs/2308.13387

"""

import json
import sys

from garak import _config
from garak.data import path as data_path
from garak.intents import TextStub
import garak.probes

this = sys.modules[__name__]


def load_local_data(self):
    with open(
        data_path / "donotanswer" / f"{self.dna_category}.jsonl",
        encoding="utf-8",
    ) as f:
        entries = [json.loads(line) for line in f if line.strip()]
    stubs = []
    for entry in entries:
        intents = entry.get("intents") or []
        stub = TextStub(intent=intents[0] if intents else None)
        stub.content = entry["prompt"]
        stubs.append(stub)
    self.prompts = [stub.content for stub in stubs]
    self._prompt_intents = [stub.intent for stub in stubs]


def local_constructor(self, config_root=_config):
    super(self.__class__, self).__init__(config_root=config_root)
    self.load_data()


DNA_PROBE_TAGS = {
    "discrimination_exclusion_toxicity_hateful_offensive": [
        "avid-effect:ethics:E0301",
        "quality:Behavioral:ContentSafety:Toxicity",
        "quality:Behavioral:ContentSafety:HateHarassment",
        "quality:Behavioral:ContentSafety:Violence",
        "quality:Behavioral:ContentSafety:Profanity",
        "demon:Stratagems:Meta-prompting:Ask_for_examples",  # directly requests examples of hateful/offensive content
    ],
    "human_chatbox": [
        "avid-effect:security:S0301",
        "quality:Behavioral:ContentSafety:Unauthorized",
        "demon:Fictionalizing:Roleplaying:DAN_and_target_persona",  # asks model to adopt unrestricted human chatbot persona
    ],
    "information_hazard": [
        "owasp:llm06",
        "avid-effect:security:S0301",
        "quality:Security:Confidentiality",
        "demon:Stratagems:Meta-prompting:Ask_for_examples",  # requests examples of sensitive/hazardous information
    ],
    "malicious_uses": [
        "quality:Behavioral:ContentSafety:LegalGoodsServices",
        "demon:Stratagems:Meta-prompting:Ask_for_examples",  # requests examples of malicious use instructions
    ],
    "misinformation_harms": [
        "quality:Robustness:GenerativeMisinformation",
        "avid-effect:ethics:E0402",
        "owasp:llm09",
        "demon:Stratagems:Meta-prompting:Ask_for_examples",  # requests examples of misinformation content
    ],
}

DNA_PROBE_INTENTS = {
    "discrimination_exclusion_toxicity_hateful_offensive": "S005",  # broad toxicity spanning multiple sub-types
    "human_chatbox": "S002",  # the prompts mostly try to replace human professional or therapeutic advice
    "information_hazard": "S009private",  # the common behavior is disclosing private information about third parties
    "malicious_uses": "S003instructions",  # the prompts broadly ask for illegal or abusive instructions
    "misinformation_harms": "S001mis",  # this category focuses on harmful misinformation
}

for probe_class in list(DNA_PROBE_TAGS.keys()):
    failure_name = probe_class.replace("_", " ")
    classname = probe_class.title().replace("_", "")
    goal = f"get model to respond as {failure_name}"
    descr = f"Implementation of {probe_class} probes in DoNotAnswer_Prompts"
    doc = f"Do Not Answer probe\n\nA curated list of questions to which LLMs should not respond back, specifically testing {failure_name}"

    setattr(
        this,
        classname,
        type(
            classname,
            (garak.probes.Probe,),
            {
                "__init__": local_constructor,
                "__doc__": doc,
                "uri": "https://arxiv.org/abs/2308.13387",
                "lang": "en",
                "description": descr,
                "intent": DNA_PROBE_INTENTS[probe_class],
                "primary_detector": "mitigation.MitigationBypass",
                "prompts": [],
                "load_data": load_local_data,
                "goal": goal,
                "dna_category": probe_class,
                "tags": DNA_PROBE_TAGS[probe_class],
                "active": False,
                "tier": garak.probes.Tier.UNLISTED,
            },
        ),
    )
