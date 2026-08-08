"""Ollama interface"""

import logging
from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import GeneratorBackoffTrigger
from garak.generators.base import Generator
from httpx import TimeoutException


def _give_up(error):
    return (
        not isinstance(error.__cause__, TimeoutException)
        and hasattr(error, "status_code")
        and error.status_code == 404
    )


class OllamaGenerator(Generator):
    """Interface for Ollama endpoints

    Model names can be passed in short form like "llama2" or specific versions or sizes like "gemma:7b" or "llama2:latest"

    suppressed_params (set[str], default empty): garak attribute names to omit from
    the Ollama request `options` dict, regardless of whether the corresponding
    attribute is set. Suppression is applied at request-assembly time, so it
    overrides per-probe parameter mutation (such as promptinject's
    _generator_precall_hook). Use garak attribute names (max_tokens, temperature,
    top_k).

    Example garak.site.yaml config to suppress top_k::

        plugins:
          generators:
            ollama:
              OllamaGenerator:
                suppressed_params:
                  - top_k
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "timeout": 30,  # Add a timeout of 30 seconds. Ollama can tend to hang forever on failures, if this is not present
        "host": "127.0.0.1:11434",  # The default host of an Ollama server. This can be overwritten with a passed config or generator config file.
        "suppressed_params": set(),
    }

    active = True
    generator_family_name = "Ollama"
    parallel_capable = False
    extra_dependency_names = ["ollama"]

    # Maps garak attribute names to (Ollama options field name, coerce fn).
    # Ollama takes generation parameters nested under `options`, and names the
    # output cap `num_predict`, so the mapping is a translation rather than a
    # passthrough.
    _PARAM_MAP = {
        "max_tokens": ("num_predict", int),
        "temperature": ("temperature", float),
        "top_k": ("top_k", int),
        "seed": ("seed", int),
    }

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)  # Sets the name and generations

        self.client = self.ollama.Client(
            self.host, timeout=self.timeout
        )  # Instantiates the client with the timeout

        self.suppressed_params = set(self.suppressed_params)
        for param in self.suppressed_params:
            if param not in self._PARAM_MAP:
                logging.warning(
                    f"suppressed_params entry '{param}' is not a known OllamaGenerator "
                    f"parameter. Valid keys are: {sorted(self._PARAM_MAP)}."
                )

    def _build_options(self):
        """Assemble the Ollama `options` dict from configured generation params.

        Returns None when nothing is set, which the ollama client treats the same
        as omitting the argument.
        """
        options = {}
        for attr, (api_field, coerce) in self._PARAM_MAP.items():
            if attr in self.suppressed_params:
                continue
            value = getattr(self, attr, None)
            if value is None:
                continue
            options[api_field] = coerce(value)
        return options or None

    @backoff.on_exception(
        backoff.fibo,
        GeneratorBackoffTrigger,
        max_value=70,
        giveup=_give_up,
    )
    @backoff.on_predicate(
        backoff.fibo, lambda ans: ans == [None] or len(ans) == 0, max_tries=3
    )  # Ollama sometimes returns empty responses. Only 3 retries to not delay generations expecting empty responses too much
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        try:
            response = self.client.generate(
                self.name,
                prompt.last_message().text,
                options=self._build_options(),
            )
        except Exception as e:
            if (
                isinstance(e, self.ollama.ResponseError) and e.status_code == 404
            ):  # send the 404 through
                raise e
            backoff_exception_types = [self.ollama.ResponseError, TimeoutException]
            for backoff_exception in backoff_exception_types:
                if isinstance(e, backoff_exception):
                    raise GeneratorBackoffTrigger from e
            raise e

        return [Message(response.get("response", None))]


class OllamaGeneratorChat(OllamaGenerator):
    """Interface for Ollama endpoints, using the chat functionality

    Model names can be passed in short form like "llama2" or specific versions or sizes like "gemma:7b" or "llama2:latest"
    """

    @backoff.on_exception(
        backoff.fibo,
        GeneratorBackoffTrigger,
        max_value=70,
        giveup=_give_up,
    )
    @backoff.on_predicate(
        backoff.fibo, lambda ans: ans == [None] or len(ans) == 0, max_tries=3
    )  # Ollama sometimes returns empty responses. Only 3 retries to not delay generations expecting empty responses too much
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        messages = self._conversation_to_list(prompt)

        try:
            response = self.client.chat(
                model=self.name,
                messages=messages,
                options=self._build_options(),
            )
        except Exception as e:
            if (
                isinstance(e, self.ollama.ResponseError) and e.status_code == 404
            ):  # send the 404 through
                raise e
            backoff_exception_types = [self.ollama.ResponseError, TimeoutException]
            for backoff_exception in backoff_exception_types:
                if isinstance(e, backoff_exception):
                    raise GeneratorBackoffTrigger from e
            raise e
        return [
            Message(response.get("message", {}).get("content", None))
        ]  # Return the response or None


DEFAULT_CLASS = "OllamaGeneratorChat"
