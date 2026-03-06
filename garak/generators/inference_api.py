# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NVIDIA Inference API LLM Interface"""

import inspect
import json
import logging
from typing import List, Union

import backoff
import openai

from garak import _config
from garak.attempt import Message, Conversation
import garak.exception
from garak.exception import GarakException
from garak.generators.openai import OpenAICompatible


class InferenceAPI(OpenAICompatible):
    """Wrapper for NVIDIA Inference API.

    Connects to the chat/completions endpoint at https://inference-api.nvidia.com.
    You must set the INFERENCE_API_KEY environment variable.

    To use this generator:

    #. Set the ``INFERENCE_API_KEY`` environment variable to your API key.

       On Linux, this might look like ``export INFERENCE_API_KEY="your-key-here"``.
    #. Run garak, setting ``--target_type 'inference_api'`` and ``--target_name`` to
       the name of the model, such as ``--target_name 'model-name'``.
    """

    ENV_VAR = "INFERENCE_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "temperature": 0.7,
        "top_p": None,  # Some models don't allow both temperature and top_p
        "uri": "https://inference-api.nvidia.com/v1/",
        "suppressed_params": {"n", "frequency_penalty", "presence_penalty", "stop"},
    }
    active = True
    supports_multiple_generations = False
    generator_family_name = "InferenceAPI"

    def _load_client(self):
        self._load_deps()
        self.client = openai.OpenAI(base_url=self.uri, api_key=self.api_key)
        if self.name in ("", None):
            raise ValueError(
                "InferenceAPI requires model name to be set, e.g. --target_name model-name"
            )
        self.generator = self.client.chat.completions

    @staticmethod
    def _conversation_to_content_list(conversation: Conversation) -> list[dict]:
        """Convert Conversation object to a list of dicts with content as list format.

        This API expects content to be [{"type": "text", "text": "..."}] instead of a plain string.
        """
        turn_list = [
            {
                "role": turn.role,
                "content": [{"type": "text", "text": turn.content.text}],
            }
            for turn in conversation.turns
        ]
        return turn_list

    @backoff.on_exception(
        backoff.fibo,
        (
            openai.RateLimitError,
            openai.InternalServerError,
            openai.APITimeoutError,
            openai.APIConnectionError,
            garak.exception.GeneratorBackoffTrigger,
        ),
        max_value=70,
    )
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if self.client is None:
            self._load_client()

        assert (
            generations_this_call == 1
        ), "generations_per_call / n > 1 is not supported"

        # Build create_args - don't include 'n' as it's suppressed
        create_args = {}
        for arg in inspect.signature(self.generator.create).parameters:
            if arg == "model":
                create_args[arg] = self.name
                continue
            if arg == "extra_params":
                continue
            if hasattr(self, arg) and arg not in self.suppressed_params:
                if getattr(self, arg) is not None:
                    create_args[arg] = getattr(self, arg)

        if hasattr(self, "extra_params"):
            for k, v in self.extra_params.items():
                create_args[k] = v

        # Convert prompt to the expected format with content as list
        if isinstance(prompt, Conversation):
            messages = self._conversation_to_content_list(prompt)
        else:
            msg = (
                f"Expected a Conversation for {self.generator_family_name}, but got {type(prompt)}. "
                f"Returning nothing!"
            )
            logging.error(msg)
            return [None]

        create_args["messages"] = messages

        try:
            response = self.generator.create(**create_args)
        except openai.BadRequestError as e:
            msg = f"Bad request: {e}"
            logging.error(msg)
            return [None]
        except json.decoder.JSONDecodeError as e:
            logging.exception(e)
            if self.retry_json:
                raise garak.exception.GeneratorBackoffTrigger from e
            else:
                raise e
        except openai.UnprocessableEntityError as uee:
            msg = "Model call didn't match endpoint expectations, see log"
            logging.critical(msg, exc_info=uee)
            raise GarakException(f"🛑 {msg}") from uee
        except openai.NotFoundError as nfe:
            msg = "Inference API endpoint not found. Is the model name spelled correctly and the endpoint URI correct?"
            logging.critical(msg, exc_info=nfe)
            raise GarakException(f"🛑 {msg}") from nfe

        if not hasattr(response, "choices"):
            logging.debug(
                "Did not get a well-formed response, retrying. Expected object with .choices member, got: '%s'"
                % repr(response)
            )
            msg = "no .choices member in generator response"
            if self.retry_json:
                raise garak.exception.GeneratorBackoffTrigger(msg)
            else:
                return [None]

        return [Message(c.message.content) for c in response.choices]


DEFAULT_CLASS = "InferenceAPI"

