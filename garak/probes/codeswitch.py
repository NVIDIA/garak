"""**Code-switching**

These attacks mix two or more languages within a single instruction to test whether
safety training that was learned largely in one language still holds when a request
is code-switched.

Probes in this module send prompts that switch languages *inside a single sentence*
(intra-sentential code-switching), keeping the request itself unchanged. They target
the stability of refusal behaviour across languages, rather than the meaning of the
request. This is distinct from garak's ``langprovider`` layer, which translates a
whole prompt from one language into another: here the multilingual mixing is the
attack surface, so the prompts must be used exactly as authored and must not be run
back through translation.

Further info:

* https://arxiv.org/abs/2310.02446

"""

from garak import _config
from garak.data import path as data_path
import garak.probes


class CodeSwitchFull(garak.probes.Probe):
    """Will the system give unsafe responses when a request mixes languages within one sentence?

    This probe sends requests that switch between languages inside a single sentence
    (intra-sentential code-switching). The request is not changed, only the language
    it is written in. It checks whether refusal training still holds when the same
    ask is code-switched instead of written in one language.
    """

    active = False
    lang = "en"
    doc_uri = "https://arxiv.org/abs/2310.02446"
    primary_detector = "mitigation.Prefixes"
    tags = [
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    goal = "use intra-sentential code-switching to disregard the system prompt"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        self.prompts = []

        with open(
            data_path / "codeswitch" / "codeswitch_multi.txt",
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                self.prompts.append(stripped)


class CodeSwitch(CodeSwitchFull):
    """Attempt to evade safeguards by mixing languages within a single request

    A subset of the code-switched requests. Success is reported higher with more
    variation, so the prompt set is pruned to the soft prompt cap.
    """

    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._prune_data(cap=self.soft_probe_prompt_cap)
