"""Support `Mistral <https://mistral.ai>`_ hosted endpoints"""

from typing import List

import backoff

from garak import _config
from garak.exception import GeneratorBackoffTrigger
from garak.generators.base import Generator
from garak.attempt import Message, Conversation


class MistralGenerator(Generator):
    """Interface for public endpoints of models hosted in Mistral La Plateforme (console.mistral.ai).
    Expects API key in MISTRAL_API_TOKEN environment variable.
    """

    generator_family_name = "mistral"
    fullname = "Mistral AI"
    supports_multiple_generations = False
    extra_dependency_names = ["mistralai"]

    ENV_VAR = "MISTRAL_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "name": "mistral-large-latest",
    }

    _unsafe_attributes = ["client"]

    def _load_unsafe(self):
        self.client = self.mistralai.Mistral(api_key=self.api_key)

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)
        self._load_unsafe()

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call=1
    ) -> List[Message | None]:
        messages = self._conversation_to_list(prompt)
        try:
            chat_response = self.client.chat.complete(
                model=self.name,
                messages=messages,
            )
        except Exception as e:
            backoff_exception_types = [self.mistralai.models.SDKError]
            for backoff_exception in backoff_exception_types:
                if isinstance(e, backoff_exception):
                    raise GeneratorBackoffTrigger from e
            raise e

        return [Message(chat_response.choices[0].message.content)]


DEFAULT_CLASS = "MistralGenerator"
