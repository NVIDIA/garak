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
        "temperature": None,
        "max_tokens": None,
        "top_p": None,
        "stop": [],
        "system": None,
    }

    generator_family_name = "LLM"

    def __init__(self, name: str = "", config_root=_config):
        self.name = name
        self._load_config(config_root)
        self.fullname = f"LLM (simonw/llm) {self.name or '(default)'}"

        super().__init__(self.name, config_root=config_root)

        try:
            # Resolve the llm model; fall back to llm's default if no name given
            self.model = llm.get_model(self.name) if self.name else llm.get_model()
        except Exception as e:
            logging.error("Failed to resolve `llm` model '%s': %s", self.name, repr(e))
            raise e

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """
        Continuation generation method for LLM integrations via `llm`.

        This calls model.prompt() once per generation and materializes the text().
        """
        text_prompt = prompt.last_message().text

        # Build kwargs only for parameters explicitly set (non-None / non-empty)
        prompt_kwargs = {}
        if self.system:
            prompt_kwargs["system"] = self.system
        if self.max_tokens is not None:
            prompt_kwargs["max_tokens"] = self.max_tokens
        if self.temperature is not None:
            prompt_kwargs["temperature"] = self.temperature
        if self.top_p is not None:
            prompt_kwargs["top_p"] = self.top_p
        if self.stop:
            prompt_kwargs["stop"] = self.stop

        try:
            response = self.model.prompt(text_prompt, **prompt_kwargs)
            out = response.text() 
            return [Message(out)]
        except Exception as e:
            logging.error("`llm` generation failed: %s", repr(e))
            return [None]


DEFAULT_CLASS = "LLMGenerator"
