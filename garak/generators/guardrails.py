# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NeMo Guardrails generator."""

from contextlib import redirect_stderr
import io
from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


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
            result = self.rails.generate(prompt.last_message().text)

        if isinstance(result, str):
            return [Message(result)]
        elif isinstance(result, dict):
            content = result.get("content", None)
            if content is not None:
                content = Message(content)
            return [content]
        else:
            return [None]


DEFAULT_CLASS = "NeMoGuardrails"
