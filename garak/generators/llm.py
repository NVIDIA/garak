# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""LLM (simonw/llm) generator support"""

import logging
from typing import List, Union

import llm 

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


class LLMGenerator(Generator):
    """Class supporting simonw/llm-managed models

    See https://pypi.org/project/llm/ and its provider plugins.

    Calls model.prompt() with the prompt text and relays the response. Per-provider
    options and API keys are all handled by `llm` (e.g., `llm keys set openai`).

    Set --model_name to the `llm` model id or alias (e.g., "gpt-4o-mini",
    "claude-3.5-haiku", or a local alias configured in `llm models`).

    Explicitly, garak delegates the majority of responsibility here:

    * the generator calls prompt() on the resolved `llm` model
    * provider setup, auth, and model-specific options live in `llm`
    * there's no support for chains; this is a direct LLM interface

    Notes:
    * Not all providers support all parameters (e.g., temperature, max_tokens).
      We pass only non-None params; providers ignore what they don't support.
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "max_tokens": None,
        "top_p": None,
        "stop": [],
    }

    generator_family_name = "llm"

    def __init__(self, name: str = "", config_root=_config):
        self.target = None
        self.name = name
        self._load_config(config_root)
        self.fullname = f"llm (simonw/llm) {self.name or '(default)'}"

        self._load_client()

        super().__init__(self.name, config_root=config_root)

        self._clear_client()

    def __getstate__(self) -> object:
        self._clear_client()
        return dict(self.__dict__)

    def __setstate__(self, data: dict) -> None:
        self.__dict__.update(data)
        self._load_client()

    def _load_client(self) -> None:
        try:
            self.target = llm.get_model(self.name) if self.name else llm.get_model()
        except Exception as exc:
            logging.error(
                "Failed to resolve `llm` target '%s': %s", self.name, repr(exc)
            )
            raise

    def _clear_client(self) -> None:
        self.target = None

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """
        Continuation generation method for LLM integrations via `llm`.

        This calls model.prompt() once per generation and materializes the text().
        """
        if self.target is None:
            self._load_client()

        system_turns = [turn for turn in prompt.turns if turn.role == "system"]
        user_turns = [turn for turn in prompt.turns if turn.role == "user"]
        assistant_turns = [turn for turn in prompt.turns if turn.role == "assistant"]

        if assistant_turns:
            raise ValueError("llm generator does not accept assistant turns")
        if len(system_turns) > 1:
            raise ValueError("llm generator supports at most one system turn")
        if len(user_turns) != 1:
            raise ValueError("llm generator requires exactly one user turn")

        text_prompt = prompt.last_message("user").text

        # Build kwargs only for parameters explicitly set (non-None / non-empty)
        prompt_kwargs = {
            key: getattr(self, key)
            for key in ("max_tokens", "temperature", "top_p")
            if getattr(self, key) is not None
        }
        if self.stop:
            prompt_kwargs["stop"] = self.stop

        try:
            response = self.target.prompt(text_prompt, **prompt_kwargs)
            out = response.text() 
            return [Message(out)]
        except Exception as e:
            logging.error("`llm` generation failed: %s", repr(e))
            return [None]


DEFAULT_CLASS = "LLMGenerator"
