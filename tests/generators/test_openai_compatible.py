# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import httpx
import logging
import respx
import pytest
import importlib
import inspect

from collections.abc import Iterable
from types import SimpleNamespace
from unittest.mock import Mock

from garak.attempt import Message, Turn, Conversation
import garak.generators.nim as nim_generator
import garak.generators.openai as openai_generator
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


class FakeCompletions:
    def __init__(self, client):
        self._client = client

    def create(self, model, prompt, n=1):
        return SimpleNamespace(
            choices=[SimpleNamespace(text="This is indeed a test")]
        )


class FakeChatCompletions:
    def __init__(self, client):
        self._client = client

    def create(self, model, messages, n=1):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content="This is a test!"))
            ]
        )


class FakeOpenAIClient:
    def __init__(self):
        self.close = Mock()
        self.completions = FakeCompletions(self)
        self.chat = SimpleNamespace(completions=FakeChatCompletions(self))


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


def build_unloaded_compatible():
    generator = OpenAICompatible.__new__(OpenAICompatible)
    generator.name = MODEL_NAME
    generator.uri = "http://localhost:8000/v1/"
    generator.api_key = ENV_VAR
    generator.generator_family_name = "OpenAICompatible"
    generator.supports_multiple_generations = False
    generator.suppressed_params = set()
    generator.extra_params = {}
    generator.retry_json = True
    return generator


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


def test_openai_reload_closes_prior_client(monkeypatch):
    generator = build_unloaded_compatible()
    prior_client = Mock()
    generator.client = None
    generator.generator = SimpleNamespace(_client=prior_client)
    new_client = FakeOpenAIClient()
    monkeypatch.setattr(openai_generator.openai, "OpenAI", lambda **kwargs: new_client)

    result = generator._call_model(
        Conversation([Turn("user", Message("first testing string"))])
    )

    prior_client.close.assert_called_once()
    assert generator.client is new_client, "reload should install the new client"
    assert result[0].text == "This is a test!", "reload should still call the target"


def test_openai_reload_without_prior_client(monkeypatch):
    generator = build_unloaded_compatible()
    generator.client = None
    generator.generator = None
    new_client = FakeOpenAIClient()
    monkeypatch.setattr(openai_generator.openai, "OpenAI", lambda **kwargs: new_client)

    result = generator._call_model(
        Conversation([Turn("user", Message("first testing string"))])
    )

    new_client.close.assert_not_called()
    assert result[0].text == "This is a test!", "first reload should call the target"


def test_openai_reload_logs_close_failure(monkeypatch, caplog):
    generator = build_unloaded_compatible()
    prior_client = Mock()
    prior_client.close.side_effect = RuntimeError("transport already closed")
    generator.client = None
    generator.generator = SimpleNamespace(_client=prior_client)
    new_client = FakeOpenAIClient()
    monkeypatch.setattr(openai_generator.openai, "OpenAI", lambda **kwargs: new_client)

    with caplog.at_level(logging.DEBUG):
        result = generator._call_model(
            Conversation([Turn("user", Message("first testing string"))])
        )

    prior_client.close.assert_called_once()
    assert (
        "OpenAI-compatible client teardown failed" in caplog.text
    ), "close failures should be logged at debug level"
    assert result[0].text == "This is a test!", "reload should continue after close error"


def test_nim_load_unsafe_closes_prior_client(monkeypatch):
    generator = nim_generator.NVOpenAICompletion.__new__(
        nim_generator.NVOpenAICompletion
    )
    prior_client = Mock()
    generator.client = prior_client
    generator.generator = None
    generator.uri = "https://integrate.api.nvidia.com/v1/"
    generator.api_key = ENV_VAR
    generator.name = MODEL_NAME
    new_client = FakeOpenAIClient()
    monkeypatch.setattr(nim_generator.openai, "OpenAI", lambda **kwargs: new_client)

    generator._load_unsafe()

    prior_client.close.assert_called_once()
    assert generator.client is new_client, "NIM reload should install the new client"
    assert (
        generator.generator is new_client.completions
    ), "NIM completion reload should update the generator resource"


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
