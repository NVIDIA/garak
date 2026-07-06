# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""LLM generator support

Wraps Simon Willison's ``llm`` library (https://pypi.org/project/llm/),
which provides a unified interface to many LLM providers via plugins.

API keys and provider configuration are managed by ``llm`` itself
(e.g. ``llm keys set openai``). Pass the ``llm`` model id or alias
as ``--target_name``:

.. code-block:: bash

   pip install llm llm-claude-3  # install llm + any provider plugins
   garak --target_type llm --target_name gpt-4o-mini
"""

import logging

import backoff

from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import GeneratorBackoffTrigger, BadGeneratorException
from garak.generators.base import Generator


class LLMGenerator(Generator):
    """Interface for llm-managed models.

    Supports any model accessible through ``llm`` and its provider plugins,
    including OpenAI, Claude, Gemini, and Ollama models. Provider setup,
    authentication, and model-specific options are handled by ``llm``.
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "top_p": None,
        "stop": [],
        "suppressed_params": set(),
        "extra_params": {},
    }

    active = True
    generator_family_name = "llm"
    parallel_capable = False

    extra_dependency_names = ["llm"]
    _unsafe_attributes = ["target"]

    def __init__(self, name="", config_root=_config):
        self.name = name
        super().__init__(name, config_root=config_root)
        self._load_unsafe()

    def _load_unsafe(self) -> None:
        if hasattr(self, "target") and self.target is not None:
            return
        try:
            self.target = (
                self.llm.get_model(self.name) if self.name else self.llm.get_model()
            )
        except self.llm.UnknownModelError as exc:
            logging.error("Failed to resolve llm model '%s': %s", self.name, repr(exc))
            raise
        self._accepted_params = self._enumerate_model_params()

    def _enumerate_model_params(self) -> set:
        """Discover which prompt options the resolved model actually supports."""
        if self.target is None:
            return set()
        options_cls = getattr(self.target, "Options", None)
        if options_cls is not None and hasattr(options_cls, "model_fields"):
            return set(options_cls.model_fields.keys()) - self.suppressed_params
        return set()

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_single(
        self, text_prompt: str, system_text: Union[str, None], prompt_kwargs: dict
    ) -> Union[Message, None]:
        """Attempt a single model generation, retrying on transient errors."""
        try:
            response = self.target.prompt(
                text_prompt, system=system_text, **prompt_kwargs
            )
            return Message(response.text())
        except self.llm.NeedsKeyException as e:
            raise BadGeneratorException(e) from e
        except Exception as e:
            if isinstance(e, self.llm.ModelError):
                raise GeneratorBackoffTrigger from e
            logging.error("llm generation failed: %s", repr(e))
            return None

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[None, Message]]:
        if self.target is None:
            self._load_unsafe()

        system_turns = [turn for turn in prompt.turns if turn.role == "system"]
        user_turns = [turn for turn in prompt.turns if turn.role == "user"]
        assistant_turns = [turn for turn in prompt.turns if turn.role == "assistant"]

        if assistant_turns:
            logging.debug("llm generator does not accept assistant turns")
            return [None] * generations_this_call
        if len(system_turns) > 1:
            logging.debug("llm generator supports at most one system turn")
            return [None] * generations_this_call
        if len(user_turns) != 1:
            logging.debug("llm generator requires exactly one user turn")
            return [None] * generations_this_call

        text_prompt = prompt.last_message("user").text

        system_text = None
        if system_turns:
            system_text = system_turns[0].content.text

        prompt_kwargs = {}
        param_map = {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "stop": self.stop,
        }
        for param_name, param_value in param_map.items():
            if param_value and param_name in self._accepted_params:
                prompt_kwargs[param_name] = param_value
        prompt_kwargs.update(self.extra_params)

        return [
            self._call_single(text_prompt, system_text, prompt_kwargs)
            for _ in range(generations_this_call)
        ]


DEFAULT_CLASS = "LLMGenerator"
