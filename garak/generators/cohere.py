"""Cohere AI model support

Support for Cohere's text generation API using ClientV2 chat interface.
A model name must be specified (e.g. 'command-r-plus'). The legacy 'command'
model default has been removed as Cohere has deprecated it.
Set the COHERE_API_KEY environment variable.

NOTE: As of Cohere v5.0.0+, the generate API is legacy and chat API is recommended.
This implementation uses cohere.ClientV2() exclusively.
"""

import logging
import warnings
from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import (
    BadGeneratorException,
    GeneratorBackoffTrigger,
    TargetNameMissingError,
)
from garak.generators.base import Generator


class CohereGenerator(Generator):
    """Interface to Cohere's python library for their text2text model.

    Expects API key in COHERE_API_KEY environment variable.

    Uses cohere.ClientV2() with the chat() API (recommended in Cohere v5+).
    """

    ENV_VAR = "COHERE_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.750,
        "k": 0,
        "p": 0.75,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0,
    }

    extra_dependency_names = ["cohere"]

    generator_family_name = "Cohere"

    _unsafe_attributes = ["generator"]

    def __init__(self, name="", config_root=_config):
        self.name = name
        self.fullname = f"Cohere {self.name}"

        super().__init__(self.name, config_root=config_root)

        if not self.name:
            raise TargetNameMissingError(
                "Model name is required for Cohere (e.g. 'command-r-plus'). "
                "The 'command' model is deprecated and will be retired."
            )

        if hasattr(self, "api_version"):
            warnings.warn(
                "api_version parameter is deprecated and ignored. "
                "All requests now use the Cohere v2 chat API (ClientV2).",
                DeprecationWarning,
                stacklevel=2,
            )

        self._load_unsafe()

    def _load_unsafe(self):
        """Initialize the Cohere ClientV2 API client.

        Called from __init__ and restored via Configurable.__setstate__ on deserialization.
        """
        self.generator = self.cohere.ClientV2(api_key=self.api_key)

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """Call the Cohere v2 chat API.

        Empty prompts return empty Message objects.
        """
        prompt_text = self._conversation_to_list(prompt)

        if not prompt_text:
            return [Message("")] * generations_this_call

        responses = []
        for _ in range(generations_this_call):
            try:
                response = self.generator.chat(
                    model=self.name,
                    messages=prompt_text,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    k=self.k,
                    p=self.p,
                    frequency_penalty=self.frequency_penalty,
                    presence_penalty=self.presence_penalty,
                )

                # Extract text from message content
                if hasattr(response, "message") and hasattr(
                    response.message, "content"
                ):
                    for content_item in response.message.content:
                        if hasattr(content_item, "text"):
                            responses.append(Message(content_item.text))
                            break
                    else:
                        logging.warning(
                            "No text content found in chat response"
                        )
                        responses.append(None)
                else:
                    logging.warning(
                        "Chat response structure doesn't match expected format"
                    )
                    responses.append(None)
            except Exception as e:
                if isinstance(e, self.cohere.errors.NotFoundError):
                    raise BadGeneratorException(
                        f"Cohere model '{self.name}' not found (404). "
                        "Check the model name is valid."
                    ) from e

                backoff_exception_types = (
                    self.cohere.errors.GatewayTimeoutError,
                    self.cohere.errors.TooManyRequestsError,
                    self.cohere.errors.ServiceUnavailableError,
                    self.cohere.errors.InternalServerError,
                )
                for backoff_exception in backoff_exception_types:
                    if isinstance(e, backoff_exception):
                        raise GeneratorBackoffTrigger from e
                logging.error(f"Chat API error: {e}")
                responses.append(None)

        return responses


DEFAULT_CLASS = "CohereGenerator"
