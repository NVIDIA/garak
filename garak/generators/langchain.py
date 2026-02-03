# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""LangChain generator support"""


from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


class LangChainLLMGenerator(Generator):
    """Class supporting LangChain LLM interfaces

    See LangChain's supported models here,
      https://python.langchain.com/docs/integrations/llms/

    Calls invoke with the prompt and relays the response. No per-LLM specific
    checking, so make sure the right environment variables are set.

    Set --target_name to the LLM type required.

    Explicitly, garak delegates the majority of responsibility here:

    * the generator calls invoke() on the LLM, which seems to be the most
      widely supported method
    * langchain-relevant environment vars need to be set up there
    * There's no support for chains, just the langchain LLM interface.
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.750,
        "k": 0,
        "p": 0.75,
        "preset": None,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0,
        "stop": [],
        "model_provider": None,
        "configurable_fields": None,
    }
    extra_dependency_names = ["langchain.chat_models"]
    generator_family_name = "LangChain"

    _unsafe_attributes = ["generator"]

    def __init__(self, name="", config_root=_config):
        self.name = name
        self._load_config(config_root)
        self.fullname = f"LangChain LLM {self.name}"

        super().__init__(self.name, config_root=config_root)
        self._load_unsafe()

    def _load_unsafe(self):
        configured_fields = {}
        if self.configurable_fields:
            for field in self.configurable_fields:
                if hasattr(self, field):
                    configured_fields[field] = getattr(self, field)

        # if not already added pass thru an configured `api_key`
        if hasattr(self, "api_key") and not configured_fields.get("api_key", None):
            configured_fields["api_key"] = self.api_key

        self.generator = self.langchain_chat_models.init_chat_model(
            self.name, configurable_fields=self.configurable_fields, **configured_fields
        )

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """
        Continuation generation method for LangChain LLM integrations.

        This calls invoke once per generation; invoke() seems to have the best
        support across LangChain LLM integrations.
        """
        conv = self._conversation_to_list(prompt)
        resp = self.generator.invoke(conv)
        return [Message(resp.content)] if hasattr(resp, "content") else [None]


DEFAULT_CLASS = "LangChainLLMGenerator"
