"""GroqChat API support"""

import random
from typing import List, Union

import openai

from garak.generators.openai import OpenAICompatible


class GroqChat(OpenAICompatible):
    """Wrapper for Groq-hosted LLM models.

    Expects GROQ_API_KEY environment variable.
    See https://console.groq.com/docs/quickstart for more info on how to set up a Groq API key
    Uses the [OpenAI-compatible API](https://console.groq.com/docs/openai)
    """

    # per https://console.groq.com/docs/openai
    # 2024.09.04, `n>1` is not supported
    ENV_VAR = "GROQ_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "temperature": 0.7,
        "top_p": 1.0,
        "uri": "https://api.groq.com/openai/v1",
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
    generator_family_name = "Groq"

    def _load_client(self):
        self.client = openai.OpenAI(base_url=self.uri, api_key=self.api_key)
        if self.name in ("", None):
            raise ValueError(
                "Groq API requires model name to be set, e.g. --model_name llama-3.1-8b-instant \nCurrent models:\n"
                + "\n - ".join(
                    sorted([entry.id for entry in self.client.models.list().data])
                )
            )
        self.generator = self.client.chat.completions

    def _call_model(
        self, prompt: str | List[dict], generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        assert (
            generations_this_call == 1
        ), "generations_per_call / n > 1 is not supported"

        if self.vary_seed_each_call:
            self.seed = random.randint(0, 65535)

        if self.vary_temp_each_call:
            self.temperature = random.random()

        return super()._call_model(prompt, generations_this_call)


DEFAULT_CLASS = "GroqChat"
