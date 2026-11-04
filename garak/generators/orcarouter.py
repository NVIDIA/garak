"""OrcaRouter API support

OrcaRouter is an OpenAI-compatible gateway that routes requests to a large
catalogue of models. Put your OrcaRouter API key in the ORCAROUTER_API_KEY
environment variable and select the model you want with the --target_name
command line parameter.

Sources:

* https://www.orcarouter.ai
* https://api.orcarouter.ai/v1
"""

from typing import List, Union

import openai

from garak.attempt import Message
from garak.generators.openai import OpenAICompatible


class OrcaRouter(OpenAICompatible):
    """Wrapper for the OrcaRouter gateway.

    Expects ORCAROUTER_API_KEY environment variable.
    Uses the OpenAI-compatible API at https://api.orcarouter.ai/v1
    """

    ENV_VAR = "ORCAROUTER_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "temperature": 0.7,
        "top_p": 1.0,
        "uri": "https://api.orcarouter.ai/v1",
        "vary_seed_each_call": True,  # encourage variation when generations>1
        "vary_temp_each_call": True,  # encourage variation when generations>1
        "suppressed_params": {
            "n",
            "frequency_penalty",
            "presence_penalty",
            "logprobs",
            "logit_bias",
            "top_logprobs",
        },
    }
    active = True
    supports_multiple_generations = False
    generator_family_name = "OrcaRouter"

    def _load_unsafe(self):
        self.client = openai.OpenAI(base_url=self.uri, api_key=self.api_key)
        if self.name in ("", None):
            raise ValueError(
                "OrcaRouter API requires model name to be set, e.g. --target_name orcarouter/auto \nCurrent models:\n"
                + "\n - ".join(
                    sorted([entry.id for entry in self.client.models.list().data])
                )
            )
        self.generator = self.client.chat.completions

    def _call_model(
        self, prompt: Message | List[dict], generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        assert (
            generations_this_call == 1
        ), "generations_per_call / n > 1 is not supported"

        if self.vary_seed_each_call:
            self.seed = self._rng.randint(0, 65535)

        if self.vary_temp_each_call:
            self.temperature = self._rng.random()

        return super()._call_model(prompt, generations_this_call)


DEFAULT_CLASS = "OrcaRouter"
