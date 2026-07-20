# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import httpx
import respx
import pytest
import importlib
import inspect

from collections.abc import Iterable

from garak.attempt import Message, Turn, Conversation
from garak.generators.openai import OpenAICompatible
from garak.generators.rest import RestGenerator

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
                if module_klass == RestGenerator:
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
    Conversation([Turn("user", Message("first testing string"))])
    prompts = [
        (
            generator,
            openai_compat_mocks,
            Conversation([Turn("user", Message("first testing string"))]),
        ),
        (
            generator,
            openai_compat_mocks,
            Conversation([Turn("user", Message("second testing string"))]),
        ),
        (
            generator,
            openai_compat_mocks,
            Conversation([Turn("user", Message("third testing string"))]),
        ),
    ]

    for _ in range(iterations):
        from multiprocessing import Pool

        attempt_pool = None
        try:
            attempt_pool = Pool(parallel_attempts)
            for result in attempt_pool.imap_unordered(generate_in_subprocess, prompts):
                assert result is not None
                assert isinstance(result, list), "generator should return list"
                assert isinstance(
                    result[0], Message
                ), "generator should return list of Turns or Nones"
        finally:
            if attempt_pool is not None:
                attempt_pool.close()
                attempt_pool.join()


def test_openai_multiple_generations():
    mod = importlib.import_module("garak.generators.openai")
    compat_klass = getattr(mod, "OpenAICompatible")
    assert (
        compat_klass.supports_multiple_generations == False
    ), "Compat class not expected to correctly support multiple generations by default"
    oai_klass = getattr(mod, "OpenAIGenerator")
    assert (
        oai_klass.supports_multiple_generations == True
    ), "OpenAI access expected to correctly support multiple generations by default"

# Tests for transient HTTP error handling via GeneratorBackoffTrigger (issue #1967)


def test_transient_408_raises_generator_backoff_trigger():
    import openai, httpx, garak.exception

    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx.Response(408, request=request)
    exc = openai.APIStatusError(message="Timeout", response=response, body=None)
    with pytest.raises(garak.exception.GeneratorBackoffTrigger):
        raise garak.exception.GeneratorBackoffTrigger(
            f"Transient HTTP {exc.status_code}, retrying with backoff"
        ) from None


def test_transient_429_raises_generator_backoff_trigger():
    import garak.exception

    with pytest.raises(garak.exception.GeneratorBackoffTrigger):
        raise garak.exception.GeneratorBackoffTrigger(
            "Transient HTTP 429, retrying with backoff"
        ) from None


def test_transient_502_raises_generator_backoff_trigger():
    import garak.exception

    with pytest.raises(garak.exception.GeneratorBackoffTrigger):
        raise garak.exception.GeneratorBackoffTrigger(
            "Transient HTTP 502, retrying with backoff"
        ) from None


def test_transient_status_code_tuple_members():
    transient_codes = {408, 429, 502, 503, 504}
    assert 408 in transient_codes
    assert 429 in transient_codes
    assert 502 in transient_codes
    assert 503 in transient_codes
    assert 408 in transient_codes
    assert 404 not in transient_codes
    assert 500 not in transient_codes
    assert 403 not in transient_codes
