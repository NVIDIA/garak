# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import httpx
import lorem
import respx
import pytest
import tiktoken
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

MODEL_NAME = "gpt-3.5-turbo"
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

        with Pool(parallel_attempts) as attempt_pool:
            for result in attempt_pool.imap_unordered(generate_in_subprocess, prompts):
                assert result is not None
                assert isinstance(result, list), "generator should return list"
                assert isinstance(
                    result[0], Message
                ), "generator should return list of Turns or Nones"


def create_prompt(prompt_length: int):
    test_large_context = ""
    encoding = tiktoken.encoding_for_model(MODEL_NAME)
    while len(encoding.encode(test_large_context)) < prompt_length:
        test_large_context += "\n" + lorem.paragraph()
    return Conversation([Turn(role="user", content=Message(test_large_context))])


TOKEN_LIMIT_EXPECTATIONS = {
    "use_max_completion_tokens": (
        100,  # prompt_length
        2048,  # max_tokens
        4096,  # context_len
        False,  # makes_request
        lambda a: a["max_completion_tokens"] <= 2048,  # check_lambda
        "request max_completion_tokens must account for prompt tokens",  # err_msg
    ),
    "use_max_tokens": (
        100,
        2048,
        4096,
        False,
        lambda a: a["max_tokens"] <= 2048,
        "request max_must account for prompt tokens",
    ),
    "suppress_tokens": (
        100,
        4096,
        2048,
        False,
        lambda a: a.get("max_completion_tokens", None) is None
        and a.get("max_tokens", None) is None,
        "request max_tokens is suppressed when larger than context length",
    ),
    "skip_request_above_user_limit": (
        4096,
        2048,
        4096,
        True,
        None,
        "a prompt larger than max_tokens must skip request",
    ),
    "skip_request_based_on_model_context": (
        4096,
        4096,
        4096,
        True,
        None,
        "a prompt larger than context_len must skip request",
    ),
}


@pytest.mark.parametrize(
    "test_conditions",
    [key for key in TOKEN_LIMIT_EXPECTATIONS.keys() if key != "use_max_tokens"],
)
def test_validate_call_model_chat_token_restrictions(
    openai_compat_mocks, test_conditions
):
    import json

    prompt_length, max_tokens, context_len, makes_request, check_lambda, err_msg = (
        TOKEN_LIMIT_EXPECTATIONS[test_conditions]
    )

    generator = build_test_instance(OpenAICompatible)
    generator._load_client()
    generator.max_tokens = max_tokens
    generator.context_len = context_len
    generator.generator = generator.client.chat.completions
    mock_url = getattr(generator, "uri", "https://api.openai.com/v1")
    with respx.mock(base_url=mock_url, assert_all_called=False) as respx_mock:
        mock_response = openai_compat_mocks["chat"]
        respx_mock.post("chat/completions").mock(
            return_value=httpx.Response(
                mock_response["code"], json=mock_response["json"]
            )
        )
        prompt_text = create_prompt(prompt_length)
        if makes_request:
            resp = generator._call_model(prompt_text)
            assert not respx_mock.routes[0].called
            assert resp == [None]
        else:
            generator._call_model(prompt_text)
            req_body = json.loads(respx_mock.routes[0].calls[0].request.content)
            assert check_lambda(req_body), err_msg


@pytest.mark.parametrize(
    "test_conditions",
    [
        key
        for key in TOKEN_LIMIT_EXPECTATIONS.keys()
        if key != "use_max_completion_tokens"
    ],
)
def test_validate_call_model_completion_token_restrictions(
    openai_compat_mocks, test_conditions
):
    import json

    prompt_length, max_tokens, context_len, makes_request, check_lambda, err_msg = (
        TOKEN_LIMIT_EXPECTATIONS[test_conditions]
    )

    generator = build_test_instance(OpenAICompatible)
    generator._load_client()
    generator.max_tokens = max_tokens
    generator.context_len = context_len
    generator.generator = generator.client.completions
    mock_url = getattr(generator, "uri", "https://api.openai.com/v1")
    with respx.mock(base_url=mock_url, assert_all_called=False) as respx_mock:
        mock_response = openai_compat_mocks["completion"]
        respx_mock.post("/completions").mock(
            return_value=httpx.Response(
                mock_response["code"], json=mock_response["json"]
            )
        )
        prompt_text = create_prompt(prompt_length)
        if makes_request:
            resp = generator._call_model(prompt_text)
            assert not respx_mock.routes[0].called
            assert resp == [None]
        else:
            generator._call_model(prompt_text)
            req_body = json.loads(respx_mock.routes[0].calls[0].request.content)
            assert check_lambda(req_body), err_msg
