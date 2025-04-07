# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import pytest

from garak import _plugins
from garak import _config
from garak.generators.base import Generator


DEFAULT_GENERATOR_NAME = "garak test"
DEFAULT_PROMPT_TEXT = "especially the lies"


GENERATORS = [
    classname for (classname, active) in _plugins.enumerate_plugins("generators")
]


def test_parallel_requests():
    _config.system.parallel_requests = 2

    g = _plugins.load_plugin("generators.test.Lipsum")
    result = g.generate(prompt="this is a test", generations_this_call=3)
    assert isinstance(result, list), "Generator generate() should return a list"
    assert len(result) == 3, "Generator should return 3 results as requested"
    assert all(
        isinstance(item, str) for item in result
    ), "All items in the generate result should be strings"
    assert all(
        len(item) > 0 for item in result
    ), "All generated strings should be non-empty"


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


def test_skip_seq():
    target_string = "TEST TEST 1234"
    test_string_with_thinking = "TEST TEST <think>not thius tho</think>1234"
    test_string_with_thinking_complex = '<think></think>TEST TEST <think>not thius tho</think>1234<think>!"(^-&$(!$%*))</think>'
    test_string_with_newlines = "<think>\n\n</think>" + target_string
    g = _plugins.load_plugin("generators.test.Repeat")
    r = g.generate(test_string_with_thinking)
    g.skip_seq_start = None
    g.skip_seq_end = None
    assert (
        r[0] == test_string_with_thinking
    ), "test.Repeat should give same output as input when no think tokens specified"
    g.skip_seq_start = "<think>"
    g.skip_seq_end = "</think>"
    r = g.generate(test_string_with_thinking)
    assert (
        r[0] == target_string
    ), "content between single skip sequence should be removed"
    r = g.generate(test_string_with_thinking_complex)
    assert (
        r[0] == target_string
    ), "content between multiple skip sequences should be removed"
    r = g.generate(test_string_with_newlines)
    assert r[0] == target_string, "skip seqs full of newlines should be removed"

    test_no_answer = "<think>not sure the output to provide</think>"
    r = g.generate(test_no_answer)
    assert r[0] == "", "Output of all skip strings should be empty"

    test_truncated_think = f"<think>thinking a bit</think>{target_string}<think>this process required a lot of details that is processed by"
    r = g.generate(test_truncated_think)
    assert r[0] == target_string, "truncated skip strings should be omitted"

    test_truncated_think_no_answer = "<think>thinking a bit</think><think>this process required a lot of details that is processed by"
    r = g.generate(test_truncated_think_no_answer)
    assert r[0] == "", "truncated skip strings should be omitted"
