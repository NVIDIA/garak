"""Do-Not-Answer Probes

https://github.com/Libr-AI/do-not-answer
https://arxiv.org/abs/2308.13387

An open-source dataset to evaluate LLMs' safety mechanism at a low cost.
The dataset consists of prompts to which language models are often trained not to answer.
"""

import sys

from garak import _config
from garak.data import path as data_path
import garak.probes

this = sys.modules[__name__]


def load_local_data(self):
    # prompts
    with open(
        data_path / "donotanswer" / f"{self.dna_category}.txt",
        encoding="utf=8",
    ) as f:
        self.prompts = f.read().strip().split("\n")


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
    ],
    "human_chatbox": [
        "avid-effect:security:S0301",
        "quality:Behavioral:ContentSafety:Unauthorized",
    ],
    "information_hazard": [
        "owasp:llm06",
        "avid-effect:security:S0301",
        "quality:Security:Confidentiality",
    ],
    "malicious_uses": [
        "quality:Behavioral:ContentSafety:LegalGoodsServices",
    ],
    "misinformation_harms": [
        "quality:Robustness:GenerativeMisinformation",
        "avid-effect:ethics:E0402",
        "owasp:llm09",
    ],
}

for probe_class in list(DNA_PROBE_TAGS.keys()):
    failure_name = probe_class.replace("_", " ")
    classname = probe_class.title().replace("_", "")
    goal = f"get model to respond as {failure_name}"
    descr = f"Implementation of {probe_class} probes in DoNotAnswer_Prompts"
    doc = f"Do Not Answer probe\n\nA curated list of questions to which LLMs should not respond back, specifically testing {failure_name}"

    # define class

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
                "primary_detector": "mitigation.MitigationBypass",
                "prompts": [],
                "load_data": load_local_data,
                "goal": goal,
                "dna_category": probe_class,
                "tags": DNA_PROBE_TAGS[probe_class],
                "active": False,  # strong content norms not applicable in many scenarios
                "tier": garak.probes.Tier.UNLISTED,
            },
        ),
    )
