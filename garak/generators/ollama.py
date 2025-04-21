"""Ollama interface"""

from typing import List, Union

import backoff
import ollama

from garak import _config
from garak.attempt import Turn
from garak.generators.base import Generator
from httpx import TimeoutException


def _give_up(error):
    return isinstance(error, ollama.ResponseError) and error.status_code == 404


class OllamaGenerator(Generator):
    """Interface for Ollama endpoints

    Model names can be passed in short form like "llama2" or specific versions or sizes like "gemma:7b" or "llama2:latest"
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "timeout": 30,  # Add a timeout of 30 seconds. Ollama can tend to hang forever on failures, if this is not present
        "host": "127.0.0.1:11434",  # The default host of an Ollama server. This can be overwritten with a passed config or generator config file.
    }

    active = True
    generator_family_name = "Ollama"
    parallel_capable = False

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)  # Sets the name and generations

        self.client = ollama.Client(
            self.host, timeout=self.timeout
        )  # Instantiates the client with the timeout

    @backoff.on_exception(
        backoff.fibo,
        (TimeoutException, ollama.ResponseError),
        max_value=70,
        giveup=_give_up,
    )
    @backoff.on_predicate(
        backoff.fibo, lambda ans: ans == [None] or len(ans) == 0, max_tries=3
    )  # Ollama sometimes returns empty responses. Only 3 retries to not delay generations expecting empty responses too much
    def _call_model(
        self, prompt: Turn, generations_this_call: int = 1
    ) -> List[Union[Turn, None]]:
        response = self.client.generate(self.name, prompt.text)
        return [Turn(response.get("response", None))]


class OllamaGeneratorChat(OllamaGenerator):
    """Interface for Ollama endpoints, using the chat functionality

    Model names can be passed in short form like "llama2" or specific versions or sizes like "gemma:7b" or "llama2:latest"
    """

    @backoff.on_exception(
        backoff.fibo,
        (TimeoutException, ollama.ResponseError),
        max_value=70,
        giveup=_give_up,
    )
    @backoff.on_predicate(
        backoff.fibo, lambda ans: ans == [None] or len(ans) == 0, max_tries=3
    )  # Ollama sometimes returns empty responses. Only 3 retries to not delay generations expecting empty responses too much
    def _call_model(
        self, prompt: Turn, generations_this_call: int = 1
    ) -> List[Union[Turn, None]]:
        response = self.client.chat(
            model=self.name,
            messages=[
                {
                    "role": "user",
                    "content": prompt.text,
                },
            ],
        )
        return [
            Turn(response.get("message", {}).get("content", None))
        ]  # Return the response or None


DEFAULT_CLASS = "OllamaGeneratorChat"
