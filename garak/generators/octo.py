# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""OctoML LLM interface"""


from typing import List, Union

import backoff
import octoai.errors

from garak import _config
from garak.generators.base import Generator


class OctoGenerator(Generator):
    """Interface for OctoAI public endpoints

    Pass the model name as `name`, e.g. llama-2-13b-chat-fp16.
    For more details, see https://octoai.cloud/tools/text.
    """

    ENV_VAR = "OCTO_API_TOKEN"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "max_tokens": 128,
        "presence_penalty": 0,
        "temperature": 0.1,
        "top_p": 1,
    }

    generator_family_name = "OctoAI"
    supports_multiple_generations = False

    def __init__(self, name="", config_root=_config):
        from octoai.client import Client

        self.name = name
        self._load_config(config_root)
        self.fullname = f"{self.generator_family_name} {self.name}"

        super().__init__(self.name, config_root=config_root)
        if self.seed is None:
            self.seed = 9

        self.client = Client(token=self.api_key)

    @backoff.on_exception(backoff.fibo, octoai.errors.OctoAIServerError, max_value=70)
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        outputs = self.client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant. Keep your responses limited to one short paragraph if possible.",
                },
                {"role": "user", "content": prompt},
            ],
            model=self.name,
            max_tokens=self.max_tokens,
            presence_penalty=self.presence_penalty,
            temperature=self.temperature,
            top_p=self.top_p,
        )

        return [outputs.choices[0].message.content]


class InferenceEndpoint(OctoGenerator):
    """Interface for OctoAI private endpoints

    Pass the model URL as the name, e.g. https://llama-2-70b-chat-xxx.octoai.run/v1/chat/completions

    This module tries to guess the internal model name in self.octo_model.
    We don't have access to private model so don't know the format.
    If garak guesses wrong, please please open a ticket.
    """

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)
        self.octo_model = "-".join(
            self.name.replace("-demo", "").replace("https://", "").split("-")[:-1]
        )

    @backoff.on_exception(backoff.fibo, octoai.errors.OctoAIServerError, max_value=70)
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        outputs = self.client.infer(
            endpoint_url=self.name,
            inputs={
                "model": self.octo_model,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                "max_tokens": self.max_tokens,
                "stream": False,
            },
        )
        return [outputs.get("choices")[0].get("message").get("content")]


DEFAULT_CLASS = "OctoGenerator"
