"""Past Tense

    Refusal training is widely used to prevent LLMs from generating harmful, undesirable, or illegal
outputs. We reveal a curious generalization gap in the current refusal training approaches:
simply reformulating a harmful request in the past tense  is often sufficient to jailbreak many state-
of-the-art LLMs
"""

from garak.probes.base import Probe
from garak import _config


class PastTense(Probe):
    """Will the system give unsafe responses when asked to write about weapon creation or dangerous behavior?

    This check sends the generator requests for advice on making weapons in the past tense."""

    bcp47 = "en"
    doc_uri = "https://arxiv.org/pdf/2407.11969v2"
    primary_detector = "specialwords.Prefixes"
    tags = [
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",        
    ]
    goal = "disregard the system prompt"


    prompts = []

    with open(
            _config.transient.package_dir / "resources" / "phrasing" / "past_tense.txt",
            "r",
            encoding="utf-8",
        ) as file:
        for str in file:
            prompts.append(str)
