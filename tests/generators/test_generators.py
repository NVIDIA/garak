# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import pytest
import random

from typing import List, Union

from garak import _plugins
from garak import _config
from garak.attempt import Turn
from garak.generators.test import Blank, Repeat, Single
from garak.generators.base import Generator

DEFAULT_GENERATOR_NAME = "garak test"
DEFAULT_PROMPT_TEXT = "especially the lies"


GENERATORS = [
    classname for (classname, active) in _plugins.enumerate_plugins("generators")
]


def test_generators_test_blank():
    g = Blank(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"), generations_this_call=5)
    assert output == [
        Turn(""),
        Turn(""),
        Turn(""),
        Turn(""),
        Turn(""),
    ], "generators.test.Blank with generations_this_call=5 should return five Turns with empty text"


def test_generators_test_repeat():
    g = Repeat(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn(DEFAULT_PROMPT_TEXT))
    assert output == [
        Turn(DEFAULT_PROMPT_TEXT)
    ], "generators.test.Repeat should send back a list of the posed prompt Turn"


def test_generators_test_single_one():
    g = Single(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"))
    assert isinstance(
        output, list
    ), "Single generator .generate() should send back a list"
    assert (
        len(output) == 1
    ), "Single.generate() without generations_this_call should send a list of length one"
    assert isinstance(
        output[0], Turn
    ), "Single generator output list should contain Turns"

    output = g._call_model(prompt=Turn("test"))
    assert isinstance(output, list), "Single generator _call_model should return a list"
    assert (
        len(output) == 1
    ), "_call_model w/ generations_this_call 1 should return a list of length 1"
    assert isinstance(
        output[0], Turn
    ), "Single generator output list should contain Turns"


def test_generators_test_single_many():
    random_generations = random.randint(2, 12)
    g = Single(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"), generations_this_call=random_generations)
    assert isinstance(
        output, list
    ), "Single generator .generate() should send back a list"
    assert (
        len(output) == random_generations
    ), "Single.generate() with generations_this_call should return equal generations"
    for i in range(0, random_generations):
        assert isinstance(
            output[i], Turn
        ), "Single generator output list should contain Turns (all positions)"


def test_generators_test_single_too_many():
    g = Single(DEFAULT_GENERATOR_NAME)
    with pytest.raises(ValueError):
        output = g._call_model(prompt=Turn("test"), generations_this_call=2)
    assert "Single._call_model should refuse to process generations_this_call > 1"


def test_generators_test_blank_one():
    g = Blank(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"))
    assert isinstance(
        output, list
    ), "Blank generator .generate() should send back a list"
    assert (
        len(output) == 1
    ), "Blank generator .generate() without generations_this_call should return a list of length 1"
    assert isinstance(
        output[0], Turn
    ), "Blank generator output list should contain Turns"
    assert output[0] == Turn(
        ""
    ), "Blank generator .generate() output list should contain Turns"


def test_generators_test_blank_many():
    g = Blank(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"), generations_this_call=2)
    assert isinstance(
        output, list
    ), "Blank generator .generate() should send back a list"
    assert (
        len(output) == 2
    ), "Blank generator .generate() w/ generations_this_call=2 should return a list of length 2"
    assert isinstance(
        output[0], Turn
    ), "Blank generator output list should contain Turnd (first position)"
    assert isinstance(
        output[1], Turn
    ), "Blank generator output list should contain Turns (second position)"
    assert output[0] == Turn(
        ""
    ), "Blank generator .generate() output list should contain Turns (first position)"
    assert output[1] == Turn(
        ""
    ), "Blank generator .generate() output list should contain Turns (second position)"


def test_parallel_requests():
    _config.system.parallel_requests = 2

    g = _plugins.load_plugin("generators.test.Lipsum")
    result = g.generate(prompt=Turn("this is a test"), generations_this_call=3)
    assert isinstance(result, list), "Generator generate() should return a list"
    assert len(result) == 3, "Generator should return 3 results as requested"
    assert all(
        isinstance(item, Turn) for item in result
    ), "All items in the generate result should be Turns"
    assert all(
        len(item.text) > 0 for item in result
    ), "All generated Turn texts should be non-empty"


@pytest.mark.parametrize("classname", GENERATORS)
def test_generator_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    g = getattr(m, classname.split(".")[-1])

    # has method _call_model
    assert "_call_model" in dir(
        g
    ), f"generator {classname} must have a method _call_model"
    # _call_model has a generations_this_call param
    assert (
        "generations_this_call" in inspect.signature(g._call_model).parameters
    ), f"{classname}._call_model() must accept parameter generations_this_call"
    assert (
        "prompt" in inspect.signature(g._call_model).parameters
    ), f"{classname}._call_model() must accept parameter prompt"
    # has method generate
    assert "generate" in dir(g), f"generator {classname} must have a method generate"
    # generate has a generations_this_call param
    assert (
        "generations_this_call" in inspect.signature(g.generate).parameters
    ), f"{classname}.generate() must accept parameter generations_this_call"
    # generate("") w/ empty string doesn't fail, does return list
    assert (
        "prompt" in inspect.signature(g.generate).parameters
    ), f"{classname}.generate() must accept parameter prompt"
    # any parameter that has a default must be supported
    unsupported_defaults = []
    if g._supported_params is not None:
        if hasattr(g, "DEFAULT_PARAMS"):
            for k, _ in g.DEFAULT_PARAMS.items():
                if k not in g._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


TESTABLE_GENERATORS = [
    classname
    for classname in GENERATORS
    if classname
    not in [
        "generators.azure.AzureOpenAIGenerator",  # requires additional env variables tested in own test class
        "generators.watsonx.WatsonXGenerator",  # requires additional env variables tested in own test class
        "generators.function.Multiple",  # requires mock local function not implemented here
        "generators.function.Single",  # requires mock local function not implemented here
        "generators.ggml.GgmlGenerator",  # validates files on disk tested in own test class
        "generators.guardrails.NeMoGuardrails",  # requires nemoguardrails as thirdy party install dependency
        "generators.huggingface.ConversationalPipeline",  # model name restrictions
        "generators.huggingface.LLaVA",  # model name restrictions
        "generators.huggingface.Model",  # model name restrictions
        "generators.huggingface.OptimumPipeline",  # model name restrictions and cuda required
        "generators.huggingface.Pipeline",  # model name restrictions
        "generators.langchain.LangChainLLMGenerator",  # model name restrictions
    ]
]


@pytest.mark.parametrize("classname", TESTABLE_GENERATORS)
def test_instantiate_generators(classname):
    category, namespace, klass = classname.split(".")
    from garak._config import GarakSubConfig

    gen_config = {
        namespace: {
            klass: {
                "name": "gpt-3.5-turbo-instruct",  # valid for OpenAI
                "api_key": "fake",
                "org_id": "fake",  # required for NeMo
                "uri": "https://example.com",  # required for rest
                "provider": "fake",  # required for LiteLLM
            }
        }
    }
    config_root = GarakSubConfig()
    setattr(config_root, category, gen_config)

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    g = getattr(m, classname.split(".")[-1])(config_root=config_root)
    assert isinstance(g, Generator)


NON_CONVERSATION_GENERATORS = [
    classname
    for classname in GENERATORS
    if not ("openai" in classname or "groq" in classname or "azure" in classname)
]


@pytest.mark.parametrize("classname", NON_CONVERSATION_GENERATORS)
def test_generator_signature(classname):
    _, namespace, klass = classname.split(".")
    m = importlib.import_module(f"garak.generators.{namespace}")
    g = getattr(m, klass)
    generate_signature = inspect.signature(g.generate)
    assert (
        generate_signature.parameters.get("prompt").annotation == Turn
    ), "generate should take a Turn and return list of Turns or Nones"
    assert (
        generate_signature.return_annotation == List[Union[None, Turn]]
    ), "generate should take a Turn and return list of Turns or Nones"
    _call_model_signature = inspect.signature(g._call_model)
    assert (
        _call_model_signature.parameters.get("prompt").annotation == Turn
    ), "_call_model should take a Turn and return list of Turns or Nones"
    assert (
        _call_model_signature.return_annotation == List[Union[None, Turn]]
    ), "_call_model should take a Turn and return list of Turns or Nones"
