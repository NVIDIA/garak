"""Support `Anthropic <https://www.anthropic.com>`_ hosted Claude models"""

import inspect
from typing import List, Tuple

import backoff

from garak import _config
from garak.exception import GeneratorBackoffTrigger
from garak.generators.base import Generator
from garak.attempt import Message, Conversation


class AnthropicGenerator(Generator):
    """Interface for Claude models served via the Anthropic API (api.anthropic.com).

    Expects an API key in the ``ANTHROPIC_API_KEY`` environment variable. Keys
    are issued at https://console.anthropic.com/.
    """

    generator_family_name = "anthropic"
    fullname = "Anthropic"
    supports_multiple_generations = False
    extra_dependency_names = ["anthropic"]

    ENV_VAR = "ANTHROPIC_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": None,
        "suppressed_params": set(),
    }

    _unsafe_attributes = ["client"]

    def _load_unsafe(self):
        self.client = self.anthropic.Anthropic(
            api_key=self.api_key, base_url=self.uri
        )

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)
        self._load_unsafe()

    @staticmethod
    def _split_system_and_messages(
        conversation: Conversation,
    ) -> Tuple[str | None, list[dict]]:
        """Split out system turns from the rest of the conversation.

        Anthropic's Messages API takes the system prompt as a top-level
        ``system`` parameter rather than a role inside ``messages``. Collect any
        ``system``-role turns, join them, and return the remaining turns as the
        messages payload.
        """
        system_parts = []
        messages = []
        for turn in conversation.turns:
            if turn.role == "system":
                system_parts.append(turn.content.text)
            else:
                messages.append({"role": turn.role, "content": turn.content.text})
        system = "\n\n".join(system_parts) if system_parts else None
        return system, messages

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        system, messages = self._split_system_and_messages(prompt)

        # Map garak's `name` onto the SDK's `model` kwarg, then let
        # `inspect.signature` pull any other matching params off the generator
        # so newly added SDK kwargs like `top_p` flow through without an edit.
        call_kwargs = {"messages": messages}
        if system is not None:
            call_kwargs["system"] = system
        for arg in inspect.signature(self.client.messages.create).parameters:
            if arg == "model":
                call_kwargs[arg] = self.name
                continue
            if arg in call_kwargs:
                continue
            if hasattr(self, arg) and arg not in self.suppressed_params:
                value = getattr(self, arg)
                if value is not None:
                    call_kwargs[arg] = value

        try:
            response = self.client.messages.create(**call_kwargs)
        except (
            self.anthropic.RateLimitError,
            self.anthropic.APIConnectionError,
            self.anthropic.APITimeoutError,
            self.anthropic.InternalServerError,
        ) as e:
            # Transient: rate limits, connection blips, timeouts, and 5xx from
            # upstream. Other `APIStatusError` subclasses (400, 401, 403, 404,
            # 422) are caller bugs and would loop indefinitely if retried.
            raise GeneratorBackoffTrigger from e

        # `content` is a list of blocks; pull the first text block we find.
        text_blocks = [
            block.text for block in response.content if hasattr(block, "text")
        ]
        if not text_blocks:
            return [None]
        return [Message(text_blocks[0])]


DEFAULT_CLASS = "AnthropicGenerator"
