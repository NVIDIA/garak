"""abliteration.ai API support"""

import base64

from garak.attempt import Conversation
from garak.exception import GarakException
from garak.generators.openai import OpenAICompatible


class AbliterationChat(OpenAICompatible):
    """Wrapper for abliteration.ai-hosted LLM models.

    Expects ``ABLIT_KEY`` environment variable.
    See https://abliteration.ai/docs/openai-compatibility for API details.
    """

    ENV_VAR = "ABLIT_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "uri": "https://api.abliteration.ai/v1",
    }
    generator_family_name = "abliteration.ai"

    @staticmethod
    def _conversation_to_list(conversation: Conversation) -> list[dict]:
        turn_list = []

        for turn in conversation.turns:
            if turn.content.data is None or not hasattr(turn.content, "data_type"):
                turn_list.append(
                    {
                        "role": turn.role,
                        "content": turn.content.text,
                    }
                )
                continue

            if turn.content.data_type[0] is None or not turn.content.data_type[
                0
            ].startswith("image/"):
                raise GarakException(
                    f"Data type {turn.content.data_type[0]} not supported."
                )

            data_b64 = base64.b64encode(turn.content.data).decode("utf-8")
            content = []
            if turn.content.text is not None:
                content.append({"type": "text", "text": turn.content.text})
            content.append(
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:{turn.content.data_type[0]};base64,{data_b64}"
                    },
                }
            )
            turn_list.append({"role": turn.role, "content": content})

        return turn_list


DEFAULT_CLASS = "AbliterationChat"
