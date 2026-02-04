"""Replicate generator interface

Generator for https://replicate.com/

Put your replicate key in an environment variable called
REPLICATE_API_TOKEN. It's found on your Replicate account
page, https://replicate.com/account.

Text-output models are supported.
"""

import os
from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import GeneratorBackoffTrigger
from garak.generators.base import Generator


class ReplicateGenerator(Generator):
    """Interface for public endpoints of models hosted in Replicate (replicate.com).

    Expects API key in REPLICATE_API_TOKEN environment variable.
    """

    ENV_VAR = "REPLICATE_API_TOKEN"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 1,
        "top_p": 1.0,
        "repetition_penalty": 1,
    }

    generator_family_name = "Replicate"
    supports_multiple_generations = False
    extra_dependency_names = ["replicate"]

    _unsafe_attributes = ["client"]

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)

        if hasattr(self, "seed") and self.seed is None:
            self.seed = 9

        if self.api_key is not None:
            # ensure the token is in the expected runtime env var
            os.environ[self.ENV_VAR] = self.api_key
        self.client = self.replicate

    def _load_unsafe(self):
        self.client = self.replicate

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if self.client is None:
            self._load_unsafe()
        try:
            response_iterator = self.client.run(
                self.name,
                # assumes a prompt will always have a Turn
                input={
                    "prompt": prompt.last_message().text,
                    "max_length": self.max_tokens,
                    "temperature": self.temperature,
                    "top_p": self.top_p,
                    "repetition_penalty": self.repetition_penalty,
                    "seed": self.seed,
                },
            )
        except Exception as e:
            backoff_exception_types = [self.replicate.exceptions.ReplicateError]
            for backoff_exception in backoff_exception_types:
                if isinstance(e, backoff_exception):
                    raise GeneratorBackoffTrigger from e
            raise e

        return [Message("".join(response_iterator))]


class InferenceEndpoint(ReplicateGenerator):
    """Interface for private Replicate endpoints.

    Expects `name` in the format of `username/deployed-model-name`.
    """

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if self.client is None:
            self._load_unsafe()
        deployment = self.client.deployments.get(self.name)
        try:
            prediction = deployment.predictions.create(
                input={
                    "prompt": prompt.last_message().text,
                    "max_length": self.max_tokens,
                    "temperature": self.temperature,
                    "top_p": self.top_p,
                    "repetition_penalty": self.repetition_penalty,
                },
            )
        except Exception as e:
            backoff_exception_types = [self.replicate.exceptions.ReplicateError]
            for backoff_exception in backoff_exception_types:
                if isinstance(e, backoff_exception):
                    raise GeneratorBackoffTrigger from e
            raise e

        prediction.wait()
        try:
            response = "".join(prediction.output)
        except TypeError as exc:
            raise IOError(
                "Replicate endpoint didn't generate an Iterable[str]-type response. Make sure the endpoint is active."
            ) from exc
        return [Message(r) for r in response]


DEFAULT_CLASS = "ReplicateGenerator"
