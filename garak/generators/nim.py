# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NVIDIA Inference Microservice LLM interface"""

import logging
import random
import os
import requests
import backoff
from typing import List, Union

import openai

from garak import _config
from garak.exception import (
    GarakException,
    RateLimitHit,
    BadGeneratorException,
    GarakBackoffTrigger,
)
from garak.generators import Generator
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


class Vision(NVOpenAIChat):
    """Wrapper for text+image to text NIMs. Expects NIM_API_KEY environment variable.

    Following generators.huggingface.LLaVa, expects prompts to be a dict with keys
    "text" and "image"; text holds the text prompt, image holds a path to the image."""

    DEFAULT_PARAMS = NVOpenAIChat.DEFAULT_PARAMS | {
        "suppressed_params": {"n", "frequency_penalty", "presence_penalty", "stop"},
        "max_image_len": 180_000,
    }

    modality = {"in": {"text", "image"}, "out": {"text"}}

    def _prepare_prompt(self, prompt):
        import base64

        if isinstance(prompt, str):
            prompt = {"text": prompt, "image": None}

        text = prompt["text"]
        image_filename = prompt["image"]
        if image_filename is not None:
            with open(image_filename, "rb") as f:
                image_b64 = base64.b64encode(f.read()).decode()

            if len(image_b64) > self.max_image_len:
                logging.error(
                    "Image %s exceeds length limit. To upload larger images, use the assets API (not yet supported)",
                    image_filename,
                )
                return None

            image_extension = prompt["image"].split(".")[-1].lower()
            if image_extension == "jpg":  # image/jpg is not a valid mimetype
                image_extension = "jpeg"
            text = (
                text + f' <img src="data:image/{image_extension};base64,{image_b64}" />'
            )
        return text


class NVMultimodal(Generator):
    """Wrapper for text + image / audio to text NIMs. Expects NIM_API_KEY environment variable.

    Expects keys to be a dict with keys 'text' (required), and 'image' or 'audio' (optional).
    Message is sent with 'role' and 'content' where content is structured as text
    followed by <img> and/or <audio> tags ala https://build.nvidia.com/microsoft/phi-4-multimodal-instruct
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": "https://integrate.api.nvidia.com/v1/chat/completions",
        "retry_5xx": True,
        "suppressed_params": {"n", "frequency_penalty", "presence_penalty", "stop"},
        "max_input_len": 180_000,
        "ratelimit_codes": [429],
        "skip_codes": [],
        "request_timeout": 60,
        "proxies": None,
        "verify_ssl": True,
        "max_tokens": 512,
        "top_p": 0.70,
        "stream": False,
    }

    ENV_VAR = "NIM_API_KEY"
    generator_family_name = "NVMultimodal"
    modality = {"in": {"text", "image", "audio"}, "out": {"text"}}
    uri = "https://integrate.api.nvidia.com/v1/chat/completions"

    def __init__(self, name="", config_root=_config):
        self._load_config(config_root)
        self.name = name
        if not hasattr(self, "headers"):
            self.headers = {}
        self.headers = self.headers | self._get_headers()
        super().__init__(self.name, config_root=config_root)

    def _get_headers(self):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        return headers

    def prepare_payload(self, text: Union[str, dict]) -> dict:
        output = {
            "model": self.name,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature if self.temperature is not None else 0.10,
            "top_p": self.top_p if self.top_p is not None else 0.70,
            "stream": False,
        }

        if isinstance(text, str):
            output["messages"] = [{"role": "user", "content": text}]
        elif isinstance(text, dict):
            import base64
            from pathlib import Path

            if "text" not in text.keys():
                raise ValueError(
                    "NVMultiModal Generator input did not have key 'text'."
                )
            prompt_string = text["text"]
            if "image" in text.keys():
                img_extension = Path(text["image"]).suffix.replace(".", "")
                with open(text["image"], "rb") as f:
                    image_b64 = base64.b64encode(f.read()).decode()
                prompt_string += (
                    f'<img src="data:image/{img_extension};base64,{image_b64}" />'
                )
            if "audio" in text.keys():
                audio_extension = Path(text["audio"]).suffix.replace(".", "")
                with open(text["audio"], "rb") as f:
                    audio_b64 = base64.b64encode(f.read()).decode()
                prompt_string += (
                    f'<audio src="data:audio/{audio_extension};base64,{audio_b64}" />'
                )
            if len(prompt_string) <= self.max_input_len:
                output["messages"] = [{"role": "user", "content": prompt_string}]
            else:
                logging.warning(
                    f"Multimodal input is too large for Generator {self.name}. Skipping."
                )
                return None

        else:
            raise TypeError(
                f"Expected `str` or `dict` type but got {type(text)} instead"
            )

        return output

    @backoff.on_exception(backoff.fibo, (GarakBackoffTrigger, RateLimitHit), max_value=70)
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Individual call to get a rest from the REST API

        :param prompt: the input to be placed into the request template and sent to the endpoint
        :type prompt: str
        """

        request_data = self.prepare_payload(prompt)
        if request_data is None:
            return [None]

        request_headers = self.headers

        req_kArgs = {
            "json": request_data,
            "headers": request_headers,
            "timeout": self.request_timeout,
            "proxies": self.proxies,
            "verify": self.verify_ssl,
        }
        try:
            resp = requests.post(self.uri, **req_kArgs)
        except UnicodeEncodeError as uee:
            # only RFC2616 (latin-1) is guaranteed
            # don't print a repr, this might leak api keys
            logging.error(
                "Only latin-1 encoding supported by HTTP RFC 2616, check headers and values for unusual chars",
                exc_info=uee,
            )
            raise BadGeneratorException from uee
        except requests.exceptions.ReadTimeout as rt:
            logging.error("Request timed out.", exc_info=rt)
            return [None]

        if resp.status_code in self.skip_codes:
            logging.debug(
                "REST skip prompt: %s - %s, uri: %s",
                resp.status_code,
                resp.reason,
                self.uri,
            )
            return [None]

        if resp.status_code in self.ratelimit_codes:
            raise RateLimitHit(
                f"Rate limited: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            )

        if str(resp.status_code)[0] == "3":
            raise NotImplementedError(
                f"REST URI redirection: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            )

        if str(resp.status_code)[0] == "4":
            raise ConnectionError(
                f"REST URI client error: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            )

        if str(resp.status_code)[0] == "5":
            error_msg = f"REST URI server error: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            if self.retry_5xx:
                raise GarakBackoffTrigger(error_msg)
            raise ConnectionError(error_msg)

        response_object = resp.json()
        try:
            response = [response_object["choices"][0]["message"]["content"]]
        except KeyError as ke:
            logging.error(
                "Failed to find proper keys in JSON response object", exc_info=ke
            )
            response = [None]
        except IndexError as ie:
            logging.error(
                "Failed to find properly structures JSON response object", exc_info=ie
            )
            response = [None]

        return response


DEFAULT_CLASS = "NVOpenAIChat"
