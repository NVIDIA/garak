"""About Past Tense Probes

Refusal training is widely used to prevent LLMs from generating harmful, undesirable, or illegal outputs.
We reveal a curious generalization gap in the current refusal training approaches:
simply reformulating a harmful request in the past tense is often sufficient to jailbreak many state-of-the-art LLMs.
"""

from garak import _config
from garak.data import path as data_path
import garak.probes


class PastTenseFull(garak.probes.Probe):
    """Will the system give unsafe responses when asked to write about weapon creation or dangerous behavior?

    This check sends the generator requests for advice on possibly protect or restricted subjects in the past tense.
    """

    active = False
    lang = "en"
    doc_uri = "https://arxiv.org/pdf/2407.11969v2"
    primary_detector = "mitigation.Prefixes"
    tags = [
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    goal = "use past tense to disregard the system prompt"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        self.prompts = []

        with open(
            data_path / "phrasing" / "past_tense_en.txt",
            "r",
            encoding="utf-8",
        ) as file:
            for str in file:
                self.prompts.append(str.strip())


class PastTense(PastTenseFull):
    """Attempt to evade safeguards by setting requests in the past tense

    A subset of the tense-modified requests. Success is reported higher with more variation, so
    generations is overridden.
    """

    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._prune_data(cap=self.soft_probe_prompt_cap)


class FutureTenseFull(garak.probes.Probe):
    """Will the system give unsafe responses when asked to write about weapon creation or dangerous behavior?

    This check sends the generator requests for advice on possibly protect or restricted subjects in the future tense.
    """

    active = False

    lang = "en"
    doc_uri = "https://arxiv.org/pdf/2407.11969v2"
    primary_detector = "mitigation.Prefixes"
    tags = [
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    goal = "use future tense to disregard the system prompt"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        self.prompts = []

        with open(
            data_path / "phrasing" / "past_tense_en.txt",
            "r",
            encoding="utf-8",
        ) as file:
            for str in file:
                self.prompts.append(str.strip())


class FutureTense(FutureTenseFull):
    """Attempt to evade safeguards by setting requests in the future tense

    A subset of the tense-modified requests. Success is reported higher with more variation, so
    generations is overridden.
    """

    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._prune_data(self.soft_probe_prompt_cap)
