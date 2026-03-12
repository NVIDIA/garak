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
   garak --model_type llm --model_name gpt-4o-mini
"""

import logging
from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
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
    }

    active = True
    generator_family_name = "llm"
    parallel_capable = False

    extra_dependency_names = ["llm"]

    def __init__(self, name="", config_root=_config):
        self.name = name
        self._load_config(config_root)
        self.fullname = f"llm {self.name}"

        super().__init__(self.name, config_root=config_root)
        self._load_client()

    def _load_client(self) -> None:
        import llm as llm_lib

        self.llm = llm_lib
        try:
            self.target = (
                self.llm.get_model(self.name) if self.name else self.llm.get_model()
            )
        except Exception as exc:
            logging.error(
                "Failed to resolve llm model '%s': %s", self.name, repr(exc)
            )
            raise

    def _clear_client(self) -> None:
        self.target = None

    def __getstate__(self) -> object:
        self._clear_client()
        return dict(self.__dict__)

    def __setstate__(self, data: dict) -> None:
        self.__dict__.update(data)
        self._load_client()

    @backoff.on_exception(backoff.fibo, Exception, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if self.target is None:
            self._load_client()

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

        prompt_kwargs = {}
        if self.temperature:
            prompt_kwargs["temperature"] = self.temperature
        if self.max_tokens:
            prompt_kwargs["max_tokens"] = self.max_tokens
        if self.top_p:
            prompt_kwargs["top_p"] = self.top_p
        if self.stop:
            prompt_kwargs["stop"] = self.stop

        outputs: List[Union[Message, None]] = []
        for _ in range(generations_this_call):
            try:
                response = self.target.prompt(text_prompt, **prompt_kwargs)
                outputs.append(Message(response.text()))
            except Exception as e:
                logging.error("llm generation failed: %s", repr(e))
                outputs.append(None)
        return outputs


DEFAULT_CLASS = "LLMGenerator"
