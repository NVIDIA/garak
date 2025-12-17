# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
from garak.generators.openai import chat_models

supported_openai = chat_models
supported_huggingface = [
    "lmsys/vicuna-13b-v1.3",
    "lmsys/vicuna-7b-v1.3",
    "mistralai/Mistral-7B-Instruct-v0.2",
    "meta-llama/Llama-2-7b-chat-hf",
]
hf_dict = {
    "vicuna": "lmsys/vicuna-13b-v1.3",
    "mistral": "mistralai/Mistral-7B-Instruct-v0.2",
    "llama2": "meta-llama/Llama-2-7b-chat-hf",
}


def load_generator(
    model_type: str,
    model_name: str,
    model_config: str,
):
    """Function to load a generator

    Parameters
    ----------
    model_type   : Model Generator type to load
    model_name   : Name of the model to load
    model_config : Generator configuration for model to load

    Returns
    -------
    Generator object

    """

    if not (model_name in supported_openai or model_name in supported_huggingface):
        msg = (
            f"{model_name} is not currently supported for TAP generation. Support is available for the following "
            f"OpenAI and HuggingFace models:\nOpenAI: {supported_openai}\nHuggingFace: {supported_huggingface}\n"
            f"Your jailbreaks will *NOT* be saved."
        )
        print(msg)

    config_root = {"generators": {}}
    model_root = config_root["generators"]
    for part in model_type.split("."):
        model_root[part] = {}
        model_root = model_root[part]
    if model_config is not None:
        model_root |= model_config
    model_root |= {"name": model_name}

    # is this mapping still needed?
    if model_name.lower() in hf_dict.keys():
        model_root["name"] = hf_dict[model_name]
    generator = _plugins.load_plugin(
        f"generators.{model_type}", config_root=config_root
    )

    return generator
