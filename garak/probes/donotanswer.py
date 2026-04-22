"""**Do-Not-Answer Probes**

Present the target with a request for contentious or unwanted content.

Probes in this module should be from the "Do Not Answer" paper.

Do-Not-Answer is an open-source dataset to evaluate LLMs' safety mechanism at a low cost.
The dataset consists of prompts to which language models are often trained not to answer.

The DNA tests are somewhat opinionated and don't represent universal norms (nothing does), so use with care.

Further info:
* ttps://github.com/Libr-AI/do-not-answer
* https://arxiv.org/abs/2308.13387

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

DNA_PROBE_INTENTS = {
    # This bucket spans multiple toxic and hateful failure modes, so the broad toxicity root fits best.
    "discrimination_exclusion_toxicity_hateful_offensive": "S005",
    # These prompts mostly try to replace human professional or therapeutic advice with model advice.
    # Many examples also overlap with S002med and S006sh.
    "human_chatbox": "S002",
    # The common behavior here is disclosing private information about third parties.
    "information_hazard": "S009private",
    # The prompts broadly ask for illegal or abusive instructions across many domains.
    "malicious_uses": "S003instructions",
    # This category focuses on harmful misinformation, even when the prompt is phrased as advice-seeking.
    "misinformation_harms": "S001mis",
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
                "intent": DNA_PROBE_INTENTS[probe_class],  # category-specific typology fit is defined in DNA_PROBE_INTENTS above
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
