# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NeMo Guardrails generator."""

from contextlib import redirect_stderr
import io
from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator
from garak.generators.openai import OpenAICompatible


class NeMoGuardrails(Generator):
    """Generator wrapper for NeMo Guardrails."""

    supports_multiple_generations = False
    generator_family_name = "Guardrails"
    extra_dependency_names = ["nemoguardrails"]

    def __init__(self, name="", config_root=_config):

        self.name = name
        self._load_config(config_root)
        self.fullname = f"Guardrails {self.name}"

        super().__init__(self.name, config_root=config_root)

        set_verbose = self.nemoguardrails.logging.verbose.set_verbose
        # Currently, we use the model_name as the path to the config
        with redirect_stderr(io.StringIO()) as f:  # quieten the tqdm
            config = self.nemoguardrails.RailsConfig.from_path(self.name)
            self.rails = self.nemoguardrails.LLMRails(config=config)

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        with redirect_stderr(io.StringIO()) as f:  # quieten the tqdm
            # should this be expanded to process all Conversation messages?
            result = self.rails.generate(messages=self._conversation_to_list(prompt))

        if isinstance(result, str):
            return [Message(result)]
        elif isinstance(result, dict):
            content = result.get("content", None)
            if content is not None:
                content = Message(content)
            return [content]
        else:
            return [None]


class NeMoGuardrailsServer(OpenAICompatible):
    """Generator for NeMo Guardrails Server

    To select specific rails in a multi rail deployment set `config_ids` to match the rail configuration names
    as documented by the `NeMo guardrails SDK <https://docs.nvidia.com/nemo/guardrails/0.21.0/run-rails/using-fastapi-server/chat-with-guardrailed-model.html#using-the-openai-python-sdk>`_.
    """

    ENV_VAR = None

    supports_multiple_generations = False
    generator_family_name = "Guardrails"

    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "uri": "http://localhost:8000/v1/",
        "config_ids": set(),
    }

    def __init__(self, name="", config_root=_config):
        self.api_key = "not-used"  # suppress any api_key from being sent as the server does not utilize one
        super().__init__(name, config_root)
        if self.extra_params and not self.extra_params.get("extra_body"):
            self.extra_params.append("extra_body")

        guardrails = None
        if self.config_ids:
            guardrails = {"config_ids": self.config_ids}
        if guardrails:
            if hasattr(self, "extra_body") and self.extra_body and self.config_ids:
                self.extra_body["guardrails"] = guardrails
            else:
                self.extra_body = {"guardrails": guardrails}


DEFAULT_CLASS = "NeMoGuardrails"
