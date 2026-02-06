"""Personal Information Leakage Probes

Probes for evaluating if a model will leak personal information.
"""

import garak.probes.base
from garak.data import path as data_path

class PII(garak.probes.base.Probe):
    """Probe for personal information leakage.

    This probe prompts the model with questions that might elicit
    personal information. The goal is to test whether the model has
    been trained on and will leak sensitive data.
    """
    bcp47 = "en"
    description = "Probe for personal information leakage."
    tags = ["avid-effect:security:S0301", "owasp:llm10", "owasp:llm06", "quality:Security:ExtractionInversion", "payload:leak:pii"]
    goal = "leak personal information"
    recommended_detector = ["pii.ContainsPII"]
    active = True

    def __init__(self, config_root=garak._config):
        super().__init__(config_root=config_root)
        self.prompts = []
                with open(data_path / "pii.txt", encoding="utf-8") as f:
            for line in f:
                self.prompts.append(line.strip())