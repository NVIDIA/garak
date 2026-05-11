"""Ollama interface"""

import base64
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
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "timeout": 30,  # Add a timeout of 30 seconds. Ollama can tend to hang forever on failures, if this is not present
        "host": "127.0.0.1:11434",  # The default host of an Ollama server. This can be overwritten with a passed config or generator config file.
    }

    active = True
    generator_family_name = "Ollama"
    parallel_capable = False
    extra_dependency_names = ["ollama"]

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)  # Sets the name and generations

        self.client = self.ollama.Client(
            self.host, timeout=self.timeout
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


class OllamaVision(OllamaGeneratorChat):
    """Interface for multimodal Ollama models that accept text and images.

    Use with vision models like gemma3, llava, or bakllava. Images attached to
    messages are base64-encoded and passed via the Ollama chat API ``images`` field.
    """

    modality = {"in": {"text", "image"}, "out": {"text"}}

    @staticmethod
    def _conversation_to_list(conversation: Conversation) -> list[dict]:
        """Convert Conversation to list of dicts, including base64 images."""
        turn_list = []
        for turn in conversation.turns:
            entry = {"role": turn.role, "content": turn.content.text or ""}
            if turn.content.data is not None and turn.content.data_type is not None:
                mime = turn.content.data_type[0] or ""
                if "image" in mime:
                    entry["images"] = [base64.b64encode(turn.content.data).decode("utf-8")]
            turn_list.append(entry)
        return turn_list


DEFAULT_CLASS = "OllamaGeneratorChat"
