"""**Tool-based Indirect Prompt Injection**

Probes for indirect prompt injection via tool responses.

Items in this module test indirect prompt injection via tool responses.
Each probe introduces a different "tool" to elicit harmful responses from targets.
"""

from garak import _config
import garak.attempt
import garak.payloads
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
        "n_replacements": 2,
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root)

        self.payloads = list()
        for payload_class in self.payload_name:
            self.payloads += garak.payloads.load(payload_class).payloads

        constructed_prompts = list()
        user_message = ""
        for payload in self.payloads:
            conversation = garak.attempt.Conversation(
                [
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
