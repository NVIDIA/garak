"""Ollama interface"""

from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import GeneratorBackoffTrigger, APIKeyMissingError
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
    """

    ENV_VAR = "OLLAMA_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "timeout": 30,  # Add a timeout of 30 seconds. Ollama can tend to hang forever on failures, if this is not present
        "host": "127.0.0.1:11434",  # The default host of an Ollama server. This can be overwritten with a passed config or generator config file.
        "verify_ssl": None,  # Whether to verify the server's ssl certificate. This might help when using self-signed certificates.
        "extra_params": None,  # Additional kwargs for the Ollama client, which are httpx.client kwargs.
    }

    active = True
    generator_family_name = "Ollama"
    parallel_capable = False
    extra_dependency_names = ["ollama"]

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)  # Sets the name and generations

        client_kwargs = {}
        if hasattr(self, "extra_params") and self.extra_params is not None:
            for k, v in self.extra_params.items():
                client_kwargs[k] = v
        if hasattr(self, "verify_ssl") and self.verify_ssl is not None:
            client_kwargs["verify"] = self.verify_ssl
        if self.api_key:
            headers = client_kwargs.get("headers", {}) | {
                "Authorization": f"Bearer {self.api_key}",
            }
            client_kwargs["headers"] = headers

        self.client = self.ollama.Client(
            self.host, timeout=self.timeout, **client_kwargs
        )  # Instantiates the client with the timeout

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
            response = self.client.generate(self.name, prompt.last_message().text)
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

    def _validate_env_var(self):
        try:
            super()._validate_env_var()
        except APIKeyMissingError as e:
            pass


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
