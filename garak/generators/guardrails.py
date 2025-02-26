# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NeMo Guardrails generator."""

from contextlib import redirect_stderr
import io
from typing import List, Union

from garak import _config
from garak.attempt import Turn
from garak.generators.base import Generator


class NeMoGuardrails(Generator):
    """Generator wrapper for NeMo Guardrails."""

    supports_multiple_generations = False
    generator_family_name = "Guardrails"

    def __init__(self, name="", config_root=_config):
        # another class that may need to skip testing due to non required dependency
        try:
            from nemoguardrails import RailsConfig, LLMRails
        except ImportError as e:
            raise NameError(
                "You must first install NeMo Guardrails using `pip install nemoguardrails`."
            ) from e

        self.name = name
        self._load_config(config_root)
        self.fullname = f"Guardrails {self.name}"

        # Currently, we use the model_name as the path to the config
        with redirect_stderr(io.StringIO()) as f:  # quieten the tqdm
            config = RailsConfig.from_path(self.name)
            self.rails = LLMRails(config=config)

        super().__init__(self.name, config_root=config_root)

    def _call_model(
        self, prompt: Turn, generations_this_call: int = 1
    ) -> List[Union[Turn, None]]:
        with redirect_stderr(io.StringIO()) as f:  # quieten the tqdm
            result = self.rails.generate(prompt)

        return [Turn(result)]


DEFAULT_CLASS = "NeMoGuardrails"
