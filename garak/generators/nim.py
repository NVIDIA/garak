# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NVIDIA Inference Microservice LLM interface"""

import logging
import random
from typing import List, Union

import openai

from garak import _config
from garak.attempt import Turn
from garak.exception import GarakException
from garak.generators.openai import OpenAICompatible


class NVOpenAIChat(OpenAICompatible):
    """Wrapper for NVIDIA-hosted NIMs. Expects NIM_API_KEY environment variable.

    Uses the [OpenAI-compatible API](https://docs.nvidia.com/ai-enterprise/nim-llm/latest/openai-api.html)
    via direct HTTP request.

    To get started with this generator:
    #. Visit [https://build.nvidia.com/explore/reasoning](build.nvidia.com/explore/reasoning)
    and find the LLM you'd like to use.
    #. On the page for the LLM you want to use (e.g. [mixtral-8x7b-instruct](https://build.nvidia.com/mistralai/mixtral-8x7b-instruct)),
    click "Get API key" key above the code snippet. You may need to create an
    account. Copy this key.
    #. In your console, Set the ``NIM_API_KEY`` variable to this API key. On
    Linux, this might look like ``export NIM_API_KEY="nvapi-xXxXxXx"``.
    #. Run garak, setting ``--model_name`` to ``nim`` and ``--model_type`` to
    the name of the model on [build.nvidia.com](https://build.nvidia.com/)
    - e.g. ``mistralai/mixtral-8x7b-instruct-v0.1``.

    """

    # per https://docs.nvidia.com/ai-enterprise/nim-llm/latest/openai-api.html
    # 2024.05.02, `n>1` is not supported
    ENV_VAR = "NIM_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "temperature": 0.1,
        "top_p": 0.7,
        "top_k": 0,  # top_k is hard set to zero as of 24.04.30
        "uri": "https://integrate.api.nvidia.com/v1/",
        "vary_seed_each_call": True,  # encourage variation when generations>1. not respected by all NIMs
        "vary_temp_each_call": True,  # encourage variation when generations>1. not respected by all NIMs
        "suppressed_params": {"n", "frequency_penalty", "presence_penalty", "timeout"},
    }
    active = True
    supports_multiple_generations = False
    generator_family_name = "NIM"

    timeout = 60

    def _load_client(self):
        self.client = openai.OpenAI(base_url=self.uri, api_key=self.api_key)
        if self.name in ("", None):
            raise ValueError(
                "NIMs require model name to be set, e.g. --model_name mistralai/mistral-8x7b-instruct-v0.1\nCurrent models:\n"
                + "\n - ".join(
                    sorted([entry.id for entry in self.client.models.list().data])
                )
            )
        self.generator = self.client.chat.completions

    def _prepare_prompt(self, prompt: Turn) -> Turn:
        return prompt

    def _call_model(
        self, prompt: Turn, generations_this_call: int = 1
    ) -> List[Union[Turn, None]]:
        assert (
            generations_this_call == 1
        ), "generations_per_call / n > 1 is not supported"

        if self.vary_seed_each_call:
            self.seed = random.randint(0, 65535)

        if self.vary_temp_each_call:
            self.temperature = random.random()

        prompt = self._prepare_prompt(prompt)
        if prompt is None:
            # if we didn't get a valid prompt, don't process it, and send the NoneType(s) downstream
            return [None] * generations_this_call

        try:
            result = super()._call_model(prompt, generations_this_call)
        except openai.UnprocessableEntityError as uee:
            msg = "Model call didn't match endpoint expectations, see log"
            logging.critical(msg, exc_info=uee)
            raise GarakException(f"🛑 {msg}") from uee
        except openai.NotFoundError as nfe:
            msg = "NIM endpoint not found. Is the model name spelled correctly and the endpoint URI correct?"
            logging.critical(msg, exc_info=nfe)
            raise GarakException(f"🛑 {msg}") from nfe
        except Exception as oe:
            msg = "NIM generation failed. Is the model name spelled correctly?"
            logging.critical(msg, exc_info=oe)
            raise GarakException(f"🛑 {msg}") from nfe

        return result

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)
        if "/" not in self.name:
            msg = "❓ Is this a valid NIM name? expected a slash-formatted name, e.g. 'org/model'"
            logging.info(msg)
            print(msg)


class NVOpenAICompletion(NVOpenAIChat):
    """Wrapper for NVIDIA-hosted NIMs. Expects NIM_API_KEY environment variable.

    Uses the [OpenAI-compatible API](https://docs.nvidia.com/ai-enterprise/nim-llm/latest/openai-api.html)
    via direct HTTP request.

    This generator supports only ``completion`` and NOT ``chat``-format models.

    To get started with this generator:
    #. Visit [build.nvidia.com/explore/reasoning](build.nvidia.com/explore/reasoning)
    and find the LLM you'd like to use.
    #. On the page for the LLM you want to use (e.g. [mixtral-8x7b-instruct](https://build.nvidia.com/mistralai/mixtral-8x7b-instruct)),
    click "Get API key" key above the code snippet. You may need to create an
    account. Copy this key.
    #. In your console, Set the ``NIM_API_KEY`` variable to this API key. On
    Linux, this might look like ``export NIM_API_KEY="nvapi-xXxXxXx"``.
    #. Run garak, setting ``--model_name`` to ``nim`` and ``--model_type`` to
    the name of the model on [build.nvidia.com](https://build.nvidia.com/)
    - e.g. ``mistralai/mixtral-8x7b-instruct-v0.1``.

    """

    def _load_client(self):
        self.client = openai.OpenAI(base_url=self.uri, api_key=self.api_key)
        self.generator = self.client.completions


class Vision(NVOpenAIChat):
    """Wrapper for text+image to text NIMs. Expects NIM_API_KEY environment variable.

    Following generators.huggingface.LLaVa, expects prompts to be a dict with keys
    "text" and "image"; text holds the text prompt, image holds a path to the image."""

    DEFAULT_PARAMS = NVOpenAIChat.DEFAULT_PARAMS | {
        "suppressed_params": {"n", "frequency_penalty", "presence_penalty", "stop"},
        "max_image_len": 180_000,
    }

    modality = {"in": {"text", "image"}, "out": {"text"}}

    def _prepare_prompt(self, turn: Turn) -> Turn:

        text = turn.text

        image_extension = "jpeg"  # guessing a default in the case of direct data

        if "image_filename" in turn.parts and "image_data" not in turn.parts:
            turn.load_image()
            image_extension = turn.parts["image_filename"].split(".")[-1].lower()
            if image_extension == "jpg":  # image/jpg is not a valid mimetype
                image_extension = "jpeg"

        if "image_data" in turn.parts:
            import base64

            image_b64 = base64.b64encode(turn.parts["image_data"]).decode()

            if len(image_b64) > self.max_image_len:
                big_img_filename = "<direct data>"
                if "image_filename" in turn.parts:
                    big_img_filename = turn.parts["image_filename"]
                logging.error(
                    "Image %s exceeds length limit. To upload larger images, use the assets API (not yet supported)",
                    big_img_filename,
                )
                return None

            text = (
                text + f' <img src="data:image/{image_extension};base64,{image_b64}" />'
            )
            turn.text = text
        return turn


DEFAULT_CLASS = "NVOpenAIChat"
