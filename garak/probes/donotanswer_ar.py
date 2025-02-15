"""
Do-Not-Answer Probes

https://github.com/Libr-AI/do-not-answer
https://arxiv.org/abs/2308.13387

An open-source dataset to evaluate LLMs' safety mechanism at a low cost.
The dataset consists of prompts to which language models are often trained not to answer.
"""

from garak import _config
from garak.data import path as data_path
from garak.probes.base import Probe


class DoNotAnswer(Probe):
    """Base class for Do Not Answer probes."""
    uri = "https://arxiv.org/abs/2308.13387"
    prompts = []
    bcp47 = "en"
    primary_detector = "mitigation.MitigationBypass"
    is_arabic = False

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.load_data()
        if self.__class__ == DoNotAnswer:
            self.run_all_subclasses()

    def load_data(self):
        """Load prompts from the corresponding category file."""
        data_dir = "ar/donotanswer" if self.is_arabic else "donotanswer"
        filepath = data_path / data_dir / f"{self.dna_category}.txt"
        with open(filepath, encoding="utf-8") as f:
            self.prompts = f.read().strip().split("\n")

    def run_all_subclasses(self):
        """Initialize and run all probe subclasses when base class is instantiated."""
        self.probe_instances = []
        for SubClass in DoNotAnswer.__subclasses__():
            probe = SubClass()
            self.probe_instances.append(probe)
        return self.probe_instances


# Common probe configuration
PROBE_CONFIGS = {
    "discrimination": {
        "name": "DiscriminationExclusionToxicityHatefulOffensive",
        "description": "Implementation of discrimination_exclusion_toxicity_hateful_offensive probes in DoNotAnswer_Prompts",
        "goal": "get model to respond as discrimination exclusion toxicity hateful offensive",
        "dna_category": "discrimination_exclusion_toxicity_hateful_offensive",
        "tags": [
            "avid-effect:ethics:E0301",
            "quality:Behavioral:ContentSafety:Toxicity",
            "quality:Behavioral:ContentSafety:HateHarassment",
            "quality:Behavioral:ContentSafety:Violence",
            "quality:Behavioral:ContentSafety:Profanity",
        ]
    },
    "human_chatbox": {
        "name": "HumanChatbox",
        "description": "Implementation of human_chatbox probes in DoNotAnswer_Prompts",
        "goal": "get model to respond as human chatbox",
        "dna_category": "human_chatbox",
        "tags": [
            "avid-effect:security:S0301",
            "quality:Behavioral:ContentSafety:Unauthorized",
        ]
    },
    "information_hazard": {
        "name": "InformationHazard",
        "description": "Implementation of information_hazard probes in DoNotAnswer_Prompts",
        "goal": "get model to respond as information hazard",
        "dna_category": "information_hazard",
        "tags": [
            "owasp:llm06",
            "avid-effect:security:S0301",
            "quality:Security:Confidentiality",
        ]
    },
    "malicious_uses": {
        "name": "MaliciousUses",
        "description": "Implementation of malicious_uses probes in DoNotAnswer_Prompts",
        "goal": "get model to respond as malicious uses",
        "dna_category": "malicious_uses",
        "tags": [
            "quality:Behavioral:ContentSafety:LegalGoodsServices",
        ]
    },
    "misinformation": {
        "name": "MisinformationHarms",
        "description": "Implementation of misinformation_harms probes in DoNotAnswer_Prompts",
        "goal": "get model to respond as misinformation harms",
        "dna_category": "misinformation_harms",
        "tags": [
            "quality:Robustness:GenerativeMisinformation",
            "avid-effect:ethics:E0402",
            "owasp:llm09",
        ]
    }
}


def create_probe_class(config, is_arabic=False):
    """Create a probe class with the given configuration."""
    class_name = config["name"]
    if is_arabic:
        class_name += "Arabic"
    
    attrs = {
        "__doc__": f"Do Not Answer probe for {config['dna_category']}.",
        "description": config["description"],
        "goal": config["goal"],
        "dna_category": config["dna_category"],
        "tags": config["tags"],
    }
    
    if is_arabic:
        attrs.update({
            "is_arabic": True,
            "bcp47": "ar",
            "primary_detector": "mitigation.MitigationBypassArabic"
        })
    
    return type(class_name, (DoNotAnswer,), attrs)


# Create English and Arabic probe classes
for config in PROBE_CONFIGS.values():
    # Create English version
    globals()[config["name"]] = create_probe_class(config, is_arabic=False)
    # Create Arabic version
    globals()[config["name"] + "Arabic"] = create_probe_class(config, is_arabic=True)