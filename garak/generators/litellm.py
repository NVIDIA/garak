"""LiteLLM model support

Support for LiteLLM, which allows calling LLM APIs using the OpenAI format.

Depending on the model name provider, LiteLLM automatically
reads API keys from the respective environment variables
such as ``OPENAI_API_KEY`` for OpenAI models.

Create a file, such as ``ollama_base.json``, with content like the following
to connect LiteLLM with the Ollama OAI API:

.. code-block:: json

   {
       "litellm": {
           "LiteLLMGenerator" : {
               "api_base" : "http://localhost:11434/v1",
               "provider" : "openai"
           }
       }
   }

When invoking garak, specify the path to the generator option file:

.. code-block:: bash

   python -m garak --target_type litellm --target_name "phi" --generator_option_file ollama_base.json -p dan
"""

import logging

from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import BadGeneratorException, GeneratorBackoffTrigger
from garak.generators.base import Generator

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
        "verbose": False,
        "suppressed_params": set(),
    }

    supports_multiple_generations = True
    generator_family_name = "LiteLLM"
    extra_dependency_names = ["litellm"]

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
        "verbose",
        "suppressed_params",
    )

    def __init__(self, name: str = "", generations: int = 10, config_root=_config):
        self.name = name
        self.api_base = None
        self.provider = None
        self._load_config(config_root)

        # Ensure suppressed_params is a set for efficient lookup
        self.suppressed_params = set(self.suppressed_params)

        self.fullname = f"LiteLLM {self.name}"
        self.supports_multiple_generations = not any(
            self.name.startswith(provider)
            for provider in unsupported_multiple_gen_providers
        )

        # Suppress log messages from LiteLLM during import
        litellm_logger = logging.getLogger("LiteLLM")
        litellm_logger.setLevel(logging.CRITICAL)

        super().__init__(self.name, config_root=config_root)

        # Fix issue with Ollama which does not support `presence_penalty`
        self.litellm.drop_params = True
        # Suppress log messages from LiteLLM
        self.litellm.verbose_logger.disabled = True
        self.litellm.set_verbose = self.verbose

    @backoff.on_exception(backoff.fibo, GeneratorBackoffTrigger, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if isinstance(prompt, Conversation):
            litellm_prompt = self._conversation_to_list(prompt)
        elif isinstance(prompt, list):
            litellm_prompt = prompt
        else:
            msg = (
                f"Expected list or Conversation for LiteLLM model {self.name}, but got {type(prompt)} instead. "
                f"Returning nothing!"
            )
            logging.error(msg)
            print(msg)
            return []

        try:
            # Build parameters dynamically, respecting suppressed_params
            params = {
                "model": self.name,
                "messages": litellm_prompt,
                "api_base": self.api_base,
                "custom_llm_provider": self.provider,
            }

            # Add optional parameters if not suppressed
            optional_params = {
                "n": generations_this_call,
                "temperature": self.temperature,
                "top_p": self.top_p,
                "stop": self.stop,
                "max_tokens": self.max_tokens,
                "frequency_penalty": self.frequency_penalty,
                "presence_penalty": self.presence_penalty,
            }

            for param_name, param_value in optional_params.items():
                if param_name not in self.suppressed_params:
                    params[param_name] = param_value

            response = self.litellm.completion(**params)
        except (
            self.litellm.exceptions.AuthenticationError,  # authentication failed for detected or passed `provider`
            self.litellm.exceptions.BadRequestError,
            self.litellm.exceptions.APIError,
        ) as e:
            raise BadGeneratorException(
                "Unrecoverable error during litellm completion; see log for details"
            ) from e
        except Exception as e:
            backoff_exception_types = [self.litellm.exceptions.APIError]
            for backoff_exception in backoff_exception_types:
                if isinstance(e, backoff_exception):
                    raise GeneratorBackoffTrigger from e
            raise e

        if self.supports_multiple_generations:
            return [Message(c.message.content) for c in response.choices]
        else:
            return [Message(response.choices[0].message.content)]


DEFAULT_CLASS = "LiteLLMGenerator"
