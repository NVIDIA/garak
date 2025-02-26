# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import httpx
import respx
import pytest
import importlib
import inspect

from collections.abc import Iterable
from garak.generators.openai import OpenAICompatible


# TODO: expand this when we have faster loading, currently to process all generator costs 30s for 3 tests
# GENERATORS = [
#     classname for (classname, active) in _plugins.enumerate_plugins("generators")
# ]
GENERATORS = [
    "generators.openai.OpenAIGenerator",
    "generators.nim.NVOpenAIChat",
    "generators.groq.GroqChat",
]

MODEL_NAME = "gpt-3.5-turbo-instruct"
ENV_VAR = os.path.abspath(
    __file__
)  # use test path as hint encase env changes are missed


def compatible() -> Iterable[OpenAICompatible]:
    for classname in GENERATORS:
        namespace = f"garak.%s" % classname[: classname.rindex(".")]
        mod = importlib.import_module(namespace)
        module_klasses = set(
            [
                (name, klass)
                for name, klass in inspect.getmembers(mod, inspect.isclass)
                if name != "Generator"
            ]
        )
        for klass_name, module_klass in module_klasses:
            if hasattr(module_klass, "active") and module_klass.active:
                if module_klass == OpenAICompatible:
                    continue
                if hasattr(module_klass, "ENV_VAR"):
                    class_instance = build_test_instance(module_klass)
                    if isinstance(class_instance, OpenAICompatible):
                        yield f"{namespace}.{klass_name}"


def build_test_instance(module_klass):
    stored_env = os.getenv(module_klass.ENV_VAR, None)
    os.environ[module_klass.ENV_VAR] = ENV_VAR
    class_instance = module_klass(name=MODEL_NAME)
    if stored_env is not None:
        os.environ[module_klass.ENV_VAR] = stored_env
    else:
        del os.environ[module_klass.ENV_VAR]
    return class_instance


# helper method to pass mock config
def generate_in_subprocess(*args):
    generator, openai_compat_mocks, prompt = args[0]
    mock_url = getattr(generator, "uri", "https://api.openai.com/v1")
    with respx.mock(base_url=mock_url, assert_all_called=False) as respx_mock:
        mock_response = openai_compat_mocks["completion"]
        respx_mock.post("/completions").mock(
            return_value=httpx.Response(
                mock_response["code"], json=mock_response["json"]
            )
        )
        mock_response = openai_compat_mocks["chat"]
        respx_mock.post("chat/completions").mock(
            return_value=httpx.Response(
                mock_response["code"], json=mock_response["json"]
            )
        )

        return generator.generate(prompt)


@pytest.mark.parametrize("classname", compatible())
def test_openai_multiprocessing(openai_compat_mocks, classname):
    parallel_attempts = 4
    iterations = 2
    namespace = classname[: classname.rindex(".")]
    klass_name = classname[classname.rindex(".") + 1 :]
    mod = importlib.import_module(namespace)
    klass = getattr(mod, klass_name)
    generator = build_test_instance(klass)
    prompts = [
        (generator, openai_compat_mocks, "first testing string"),
        (generator, openai_compat_mocks, "second testing string"),
        (generator, openai_compat_mocks, "third testing string"),
    ]

    for _ in range(iterations):
        from multiprocessing import Pool

        with Pool(parallel_attempts) as attempt_pool:
            for result in attempt_pool.imap_unordered(generate_in_subprocess, prompts):
                assert result is not None


def test_validate_call_model_token_restrictions(openai_compat_mocks):
    import lorem
    import json
    from garak.exception import GarakException

    generator = build_test_instance(OpenAICompatible)
    mock_url = getattr(generator, "uri", "https://api.openai.com/v1")
    with respx.mock(base_url=mock_url, assert_all_called=False) as respx_mock:
        mock_response = openai_compat_mocks["chat"]
        respx_mock.post("chat/completions").mock(
            return_value=httpx.Response(
                mock_response["code"], json=mock_response["json"]
            )
        )
        generator._call_model("test values")
        resp_body = json.loads(respx_mock.routes[0].calls[0].request.content)
        assert (
            resp_body["max_tokens"] < generator.max_tokens
        ), "request max_tokens must account for prompt tokens"

        test_large_context = ""
        while len(test_large_context.split()) < generator.max_tokens:
            test_large_context += "\n".join(lorem.paragraph())
        large_context_len = len(test_large_context.split())
        with pytest.raises(GarakException) as exc_info:
            generator._call_model(test_large_context)
        assert "cannot be created" in str(
            exc_info.value
        ), "a prompt larger than max_tokens must raise exception"

        generator.context_len = large_context_len * 2
        generator.max_tokens = generator.context_len - (large_context_len / 2)
        generator._call_model("test values")
        resp_body = json.loads(respx_mock.routes[0].calls[1].request.content)
        assert (
            resp_body["max_tokens"] < generator.context_len
        ), "request max_tokens must be less than model context length"
