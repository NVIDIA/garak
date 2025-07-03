# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""LangChain generator support"""


import logging
from typing import List, Union


import langchain.llms

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


class LangChainLLMGenerator(Generator):
    """Class supporting LangChain LLM interfaces

    See LangChain's supported models here,
      https://python.langchain.com/docs/integrations/llms/

    Calls invoke with the prompt and relays the response. No per-LLM specific
    checking, so make sure the right environment variables are set.

    Set --model_name to the LLM type required.

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
    }

    generator_family_name = "LangChain"

    def __init__(self, name="", config_root=_config):
        self.name = name
        self._load_config(config_root)
        self.fullname = f"LangChain LLM {self.name}"

        super().__init__(self.name, config_root=config_root)

        try:
            # this might need some special handling to allow tests
            llm = getattr(langchain.llms, self.name)()
        except Exception as e:
            logging.error("Failed to import Langchain module: %s", repr(e))
            raise e

        self.generator = llm

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """
        Continuation generation method for LangChain LLM integrations.

        This calls invoke once per generation; invoke() seems to have the best
        support across LangChain LLM integrations.
        """
        # Should this be expanded to process a whole conversation in some way?
        return [Message(r) for r in self.generator.invoke(prompt.last_message().text)]


DEFAULT_CLASS = "LangChainLLMGenerator"
