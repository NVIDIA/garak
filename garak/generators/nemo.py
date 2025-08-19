# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NeMo LLM interface"""

import json
import logging
import os
import random
import requests
from typing import List, Union

import backoff
import nemollm

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import APIKeyMissingError
from garak.generators.base import Generator


class NeMoGenerator(Generator):
    """Wrapper for the NVIDIA NeMo models via NGC. Expects NGC_API_KEY and ORG_ID environment variables."""

    ENV_VAR = "NGC_API_KEY"
    ORG_ENV_VAR = "ORG_ID"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.9,
        "top_p": 1.0,
        "top_k": 2,
        "repetition_penalty": 1.1,  # between 1 and 2 incl., or none
        "beam_search_diversity_rate": 0.0,
        "beam_width": 1,
        "length_penalty": 1,
        "guardrail": None,  # NotImplemented in library
        "api_uri": "https://api.llm.ngc.nvidia.com/v1",
    }

    supports_multiple_generations = False
    generator_family_name = "NeMo"

    def __init__(self, name=None, config_root=_config):
        self.name = name
        self.org_id = None
        self._load_config(config_root)
        self.fullname = f"NeMo {self.name}"

        super().__init__(self.name, config_root=config_root)

        self.nemo = nemollm.api.NemoLLM(
            api_host=self.api_uri, api_key=self.api_key, org_id=self.org_id
        )

        if self.name is None:
            print(json.dumps(self.nemo.list_models(), indent=2))
            raise ValueError("Please specify a NeMo model - see list above")

    def _validate_env_var(self):
        if self.org_id is None:
            if not hasattr(self, "org_env_var"):
                self.org_env_var = self.ORG_ENV_VAR
            self.org_id = os.getenv(self.org_env_var, None)

        if self.org_id is None:
            raise APIKeyMissingError(
                f'Put your org ID in the {self.org_env_var} environment variable (this was empty)\n \
                e.g.: export {self.org_env_var}="xxxx8yyyy/org-name"\n \
                Check "view code" on https://llm.ngc.nvidia.com/playground to see the ID'
            )

        return super()._validate_env_var()

    @backoff.on_exception(
        backoff.fibo,
        (
            nemollm.error.ServerSideError,
            nemollm.error.TooManyRequestsError,
            requests.exceptions.ConnectionError,  # hopefully handles SSLV3_ALERT_BAD_RECORD_MAC
        ),
        max_value=70,
    )
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        # avoid:
        #    doesn't match schema #/components/schemas/CompletionRequestBody: Error at "/prompt": minimum string length is 1
        if prompt.last_message().text == "":
            return [None]

        reset_none_seed = False
        if self.seed is None:  # nemo gives the same result every time
            reset_none_seed = True
            self.seed = random.randint(0, 2147483648 - 1)
        elif generations_this_call > 1:
            logging.info(
                "fixing a seed means nemollm gives the same result every time, recommend setting generations=1"
            )

        # can this be expanded to take a conversation set of Messages?
        response = self.nemo.generate(
            model=self.name,
            prompt=prompt.last_message().text,
            tokens_to_generate=self.max_tokens,
            temperature=self.temperature,
            random_seed=self.seed,
            top_p=self.top_p,
            top_k=self.top_k,
            # stop=["\n"],
            repetition_penalty=self.repetition_penalty,
            beam_search_diversity_rate=self.beam_search_diversity_rate,
            beam_width=self.beam_width,
            length_penalty=self.length_penalty,
            # guardrail=self.guardrail
        )

        if reset_none_seed:
            self.seed = None

        return [Message(response["text"])]


DEFAULT_CLASS = "NeMoGenerator"
