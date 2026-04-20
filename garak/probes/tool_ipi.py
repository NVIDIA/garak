"""**Tool-based Indirect Prompt Injection**

Probes for indirect prompt injection via tool responses.

Items in this module test indirect prompt injection via tool responses.
Each probe introduces a different "tool" to elicit harmful responses from targets.
"""

import random

from garak import _config
import garak.attempt
import garak.payloads
from garak.resources.common import load_contexts
import garak.probes


class WebSearch(garak.probes.Probe):
    """WebSearch tool indirect prompt injection

    asdfadsfasdfadsf placeholder description
    """

    lang = "en"
    doc_uri = ""
    primary_detector = "mitigation.MitigationBypass"
    tags = [
        "avid-effect:security:S0403",
        "avid-effect:performance:P0204",
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    goal = "disregard the system prompt"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "payload_name": ["harmful_behaviors"],
        "contexts": ["whatever"],
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root)

        payloads = list()

        for payload_class in self.payload_name:
            payloads += garak.payloads.load(payload_class).payloads

        self.payloads = self._expand_payloads(payloads)

        # Maybe we want this to be configurable?
        self.user_messages = garak.payloads.load("normal_instructions").payloads

        constructed_prompts = list()
        for payload in self.payloads:
            # Pick a random user message from normal instructions.
            user_message = random.choice(self.user_messages)
            conversation = garak.attempt.Conversation(
                [
                    garak.attempt.Turn(
                        role="system",
                        content=garak.attempt.Message(text=self.system_override),
                    ),
                    garak.attempt.Turn(
                        role="user", content=garak.attempt.Message(text=user_message)
                    ),
                    garak.attempt.Turn(
                        role="assistant",
                        content=garak.attempt.Message(
                            tool_calls=[
                                {
                                    "type": "function",
                                    "function": {
                                        "name": "web_search",
                                        "arguments": user_message,
                                    },
                                }
                            ]
                        ),
                    ),
                    garak.attempt.Turn(
                        role="tool",
                        name="web_search",
                        content=garak.attempt.Message(text=payload),
                    ),
                ]
            )
            constructed_prompts.append(conversation)

        self.prompts = constructed_prompts

    def _expand_payloads(self, payloads: list[str]) -> list[str]:
        expanded_payloads = list()
        preamble = "The following was the top ranked result for the user's query.\n"
        contexts = self._get_contexts()

        for payload in payloads:
            context1, context2 = random.choices(contexts, k=2)
            expanded = "\n".join([preamble, context1, payload, context2])
            expanded_payloads.append(expanded)

        return expanded_payloads

    def _get_contexts(self) -> list[str]:
        contexts = list()
        for context_name in self.contexts:
            contexts += load_contexts(context_name)
        return contexts
