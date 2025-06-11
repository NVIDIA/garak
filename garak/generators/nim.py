# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NVIDIA Inference Microservice LLM interface"""

import logging
import random
from typing import List, Union

import openai

from garak import _config
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

    def _prepare_prompt(self, prompt):
        return prompt

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
        #        except openai.NotFoundError as oe:
        except Exception as oe:  # too broad
            msg = "NIM generation failed. Is the model name spelled correctly?"
            logging.critical(msg, exc_info=oe)
            raise GarakException(f"🛑 {msg}") from oe

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


class NVMultimodal(NVOpenAIChat):
    """Wrapper for text + image / audio to text NIMs. Expects NIM_API_KEY environment variable.

    Expects keys to be a dict with keys 'text' (required), and 'image' or 'audio' (optional).
    Message is sent with 'role' and 'content' where content is structured as text
    followed by <img> and/or <audio> tags ala https://build.nvidia.com/microsoft/phi-4-multimodal-instruct
    """

    DEFAULT_PARAMS = NVOpenAIChat.DEFAULT_PARAMS | {
        "suppressed_params": {"n", "frequency_penalty", "presence_penalty", "stop"},
        "max_input_len": 180_000,
    }

    modality = {"in": {"text", "image", "audio"}, "out": {"text"}}

    def _prepare_prompt(self, prompt: Union[str, dict]) -> str:
        import base64
        from pathlib import Path

        if isinstance(prompt, str):
            text = prompt
        elif isinstance(prompt, dict):
            try:
                prompt_string = prompt["text"]
                data_len = 0
            except KeyError as e:
                logging.error("`prompt` input requires 'text' field for Generator %s" % self.name, exc_info=e)
                raise KeyError("`prompt` input requires 'text' field for Generator %s" % self.name)

            if "image" in prompt.keys() and prompt["image"] is not None:
                img_extension = Path(prompt["image"]).suffix.replace(".", "")
                if img_extension == "jpg":  # image/jpg is not a valid mimetype
                    image_extension = "jpeg"
                with open(prompt["image"], "rb") as f:
                    image_b64 = base64.b64encode(f.read()).decode()
                prompt_string += (
                    f'<img src="data:image/{img_extension};base64,{image_b64}" />'
                )
                data_len += len(image_b64)
            else:
                prompt["image"] = None
            if "audio" in prompt.keys() and prompt["audio"] is not None:
                audio_extension = Path(prompt["audio"]).suffix.replace(".", "")
                with open(prompt["audio"], "rb") as f:
                    audio_b64 = base64.b64encode(f.read()).decode()
                prompt_string += (
                    f'<audio src="data:audio/{audio_extension};base64,{audio_b64}" />'
                )
                data_len += len(audio_b64)
            else:
                prompt["audio"] = None

            if data_len > self.max_input_len:
                msg = (f"Data exceeds length limit. `max_input_len` is {self.max_input_len}. "
                       f"Current data size is {data_len}. "
                       f"To upload larger images or audio files, use the assets API (not yet supported)")
                if prompt["image"] is not None:
                    msg += f" Image file: {prompt['image']}"
                if prompt["audio"] is not None:
                    msg += f" Audio file: {prompt['audio']}"
                logging.error(msg)
                return None
            text = prompt_string

        else:
            raise TypeError(f"{self.name} accepts `str` and `dict` type inputs but got {type(prompt)} instead.")

        return text


class Vision(NVMultimodal):
    """Wrapper for text+image to text NIMs. Expects NIM_API_KEY environment variable.

    Following generators.huggingface.LLaVa, expects prompts to be a dict with keys
    "text" and "image"; text holds the text prompt, image holds a path to the image."""

    modality = {"in": {"text", "image"}, "out": {"text"}}


DEFAULT_CLASS = "NVOpenAIChat"
