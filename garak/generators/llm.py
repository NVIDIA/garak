# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""LLM (simonw/llm) generator support"""

import inspect
import logging
from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


class LLMGenerator(Generator):
    """Class supporting simonw/llm-managed models

    See https://pypi.org/project/llm/ and its provider plugins.

    Calls model.prompt() with the prompt text and relays the response. Per-provider
    options and API keys are all handled by `llm` (e.g., `llm keys set openai`).

    Set --target_name to the `llm` model id or alias (e.g., "gpt-4o-mini",
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
        "top_p": None,
        "stop": [],
    }

    generator_family_name = "llm"
    parallel_capable = False

    extra_dependency_names = ["llm"]

    def __init__(self, name: str = "", config_root=_config):
        self.target = None
        self.name = name
        self._load_config(config_root)
        self.fullname = f"llm (simonw/llm) {self.name or '(default)'}"

        super().__init__(self.name, config_root=config_root)
        self._load_client()

    def __getstate__(self) -> object:
        self._clear_client()
        return dict(self.__dict__)

    def __setstate__(self, data: dict) -> None:
        self.__dict__.update(data)
        self._load_client()

    def _load_client(self) -> None:
        try:
            self.target = (
                self.llm.get_model(self.name) if self.name else self.llm.get_model()
            )
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
        try:
            signature = inspect.signature(self.target.prompt)
            accepted_params = signature.parameters
            accepts_var_kwargs = any(
                param.kind == inspect.Parameter.VAR_KEYWORD
                for param in accepted_params.values()
            )
        except (TypeError, ValueError):
            accepted_params = {}
            accepts_var_kwargs = False

        if accepted_params:
            for key, param in accepted_params.items():
                if key in {"prompt", "prompt_text", "text", "self"}:
                    continue
                if not hasattr(self, key):
                    continue
                value = getattr(self, key)
                if value is None:
                    continue
                if key == "stop" and not value:
                    continue
                prompt_kwargs[key] = value

        # Fallback to a conservative parameter subset if signature inspection fails
        # or the target accepts arbitrary kwargs (so we should pass anything we have)
        fallback_keys = ("max_tokens", "temperature", "top_p")
        needs_fallback = not prompt_kwargs or accepts_var_kwargs or not accepted_params
        if needs_fallback:
            for key in fallback_keys:
                if key in prompt_kwargs:
                    continue
                value = getattr(self, key, None)
                if value is not None:
                    prompt_kwargs[key] = value
            stop_value = getattr(self, "stop", None)
            if stop_value:
                prompt_kwargs.setdefault("stop", stop_value)

        outputs: List[Union[Message, None]] = []
        for _ in range(generations_this_call):
            try:
                response = self.target.prompt(text_prompt, **prompt_kwargs)
                out = response.text()
                outputs.append(Message(out))
            except Exception as e:
                logging.error("`llm` generation failed: %s", repr(e))
                outputs.append(None)
        return outputs


DEFAULT_CLASS = "LLMGenerator"
