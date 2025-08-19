"""Replicate generator interface

Generator for https://replicate.com/

Put your replicate key in an environment variable called
REPLICATE_API_TOKEN. It's found on your Replicate account
page, https://replicate.com/account.

Text-output models are supported.
"""

import importlib
import os
from typing import List, Union

import backoff
import replicate.exceptions

from garak import _config
from garak.attempt import Message, Conversation
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

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)

        if hasattr(self, "seed") and self.seed is None:
            self.seed = 9

        if self.api_key is not None:
            # ensure the token is in the expected runtime env var
            os.environ[self.ENV_VAR] = self.api_key
        self.client = importlib.import_module("replicate")

    # avoid attempt to pickle the client attribute
    def __getstate__(self) -> object:
        self._clear_client()
        return dict(self.__dict__)

    # restore the client attribute
    def __setstate__(self, d) -> object:
        self.__dict__.update(d)
        self._load_client()

    def _load_client(self):
        self.client = importlib.import_module("replicate")

    def _clear_client(self):
        self.client = None

    @backoff.on_exception(
        backoff.fibo, replicate.exceptions.ReplicateError, max_value=70
    )
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if self.client is None:
            self.client = importlib.import_module("replicate")
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
        return [Message("".join(response_iterator))]


class InferenceEndpoint(ReplicateGenerator):
    """Interface for private Replicate endpoints.

    Expects `name` in the format of `username/deployed-model-name`.
    """

    @backoff.on_exception(
        backoff.fibo, replicate.exceptions.ReplicateError, max_value=70
    )
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if self.client is None:
            self.client = importlib.import_module("replicate")
        deployment = self.client.deployments.get(self.name)
        prediction = deployment.predictions.create(
            # assumes a prompt will always have a Turn
            input={
                "prompt": prompt.last_message().text,
                "max_length": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
                "repetition_penalty": self.repetition_penalty,
            },
        )
        prediction.wait()
        try:
            response = "".join(prediction.output)
        except TypeError as exc:
            raise IOError(
                "Replicate endpoint didn't generate a response. Make sure the endpoint is active."
            ) from exc
        return [Message(r) for r in response]


DEFAULT_CLASS = "ReplicateGenerator"
