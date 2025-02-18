"""LiteLLM model support

Support for LiteLLM, which allows calling LLM APIs using the OpenAI format.

Depending on the model name provider, LiteLLM automatically
reads API keys from the respective environment variables.
(e.g. OPENAI_API_KEY for OpenAI models)

e.g Supply a JSON like this for Ollama's OAI api:
```json
{
    "litellm": {
        "LiteLLMGenerator" : {
            "api_base" : "http://localhost:11434/v1",
            "provider" : "openai"
        }
    }
}
```

The above is an example of a config to connect LiteLLM with Ollama's OpenAI compatible API.

Then, when invoking garak, we pass it the path to the generator option file.

```
python -m garak --model_type litellm --model_name "phi" --generator_option_file ollama_base.json -p dan
```
"""

import logging

from os import getenv
from typing import List, Union

import backoff

# Suppress log messages from LiteLLM during import
litellm_logger = logging.getLogger("LiteLLM")
litellm_logger.setLevel(logging.CRITICAL)
import litellm

from garak import _config
from garak.exception import BadGeneratorException
from garak.generators.base import Generator

# Fix issue with Ollama which does not support `presence_penalty`
litellm.drop_params = True
# Suppress log messages from LiteLLM
litellm.verbose_logger.disabled = True
# litellm.set_verbose = True

# Based on the param support matrix below:
# https://docs.litellm.ai/docs/completion/input
# Some providers do not support the `n` parameter
# and thus cannot generate multiple completions in one request
unsupported_multiple_gen_providers = (
    "openrouter/",
    "claude",
    "replicate/",
    "bedrock",
    "petals",
    "palm/",
    "together_ai/",
    "text-bison",
    "text-bison@001",
    "chat-bison",
    "chat-bison@001",
    "chat-bison-32k",
    "code-bison",
    "code-bison@001",
    "code-gecko@001",
    "code-gecko@latest",
    "codechat-bison",
    "codechat-bison@001",
    "codechat-bison-32k",
)


class LiteLLMGenerator(Generator):
    """Generator wrapper using LiteLLM to allow access to different providers using the OpenAI API format."""

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.7,
        "top_p": 1.0,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0,
        "stop": ["#", ";"],
    }

    supports_multiple_generations = True
    generator_family_name = "LiteLLM"

    _supported_params = (
        "name",
        "context_len",
        "max_tokens",
        "api_key",
        "provider",
        "api_base",
        "temperature",
        "top_p",
        "top_k",
        "frequency_penalty",
        "presence_penalty",
        "skip_seq_start",
        "skip_seq_end",
        "stop",
    )

    def __init__(self, name: str = "", generations: int = 10, config_root=_config):
        self.name = name
        self.api_base = None
        self.provider = None
        self._load_config(config_root)
        self.fullname = f"LiteLLM {self.name}"
        self.supports_multiple_generations = not any(
            self.name.startswith(provider)
            for provider in unsupported_multiple_gen_providers
        )

        super().__init__(self.name, config_root=config_root)

    @backoff.on_exception(backoff.fibo, litellm.exceptions.APIError, max_value=70)
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        if isinstance(prompt, str):
            prompt = [{"role": "user", "content": prompt}]
        elif isinstance(prompt, list):
            prompt = prompt
        else:
            msg = (
                f"Expected a list of dicts for LiteLLM model {self.name}, but got {type(prompt)} instead. "
                f"Returning nothing!"
            )
            logging.error(msg)
            print(msg)
            return []

        try:
            response = litellm.completion(
                model=self.name,
                messages=prompt,
                temperature=self.temperature,
                top_p=self.top_p,
                n=generations_this_call,
                stop=self.stop,
                max_tokens=self.max_tokens,
                frequency_penalty=self.frequency_penalty,
                presence_penalty=self.presence_penalty,
                api_base=self.api_base,
                custom_llm_provider=self.provider,
            )
        except (
            litellm.exceptions.AuthenticationError,  # authentication failed for detected or passed `provider`
            litellm.exceptions.BadRequestError,
        ) as e:

            raise BadGeneratorException(
                "Unrecoverable error during litellm completion see log for details"
            ) from e

        if self.supports_multiple_generations:
            return [c.message.content for c in response.choices]
        else:
            return [response.choices[0].message.content]


DEFAULT_CLASS = "LiteLLMGenerator"
