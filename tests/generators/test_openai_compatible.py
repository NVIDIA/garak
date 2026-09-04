# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import errno
import json
import os
import httpx
import openai
import pathlib
import respx
import pytest
import importlib
import inspect
from unittest.mock import MagicMock, patch

from collections.abc import Iterable

import garak.exception
from garak.attempt import Message, Turn, Conversation
import garak.generators.openai as openai_generator
from garak.generators.openai import (
    OpenAICompatible,
    OpenAIGenerator,
    OpenAIResponsesGenerator,
)
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

IMAGE_ASSET = pathlib.Path(__file__).parents[1] / "_assets" / "tinytrans.gif"


class FileDescriptorTransport(httpx.BaseTransport):
    def __init__(self):
        self.fd = None

    def handle_request(self, request):
        self.fd = os.open(os.devnull, os.O_RDONLY)
        payload = {
            "choices": [
                {
                    "message": {"content": "This is a test!", "role": "assistant"},
                    "finish_reason": "stop",
                    "index": 0,
                }
            ],
            "created": 0,
            "id": "test",
            "model": MODEL_NAME,
            "object": "chat.completion",
        }
        return httpx.Response(
            200,
            content=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            request=request,
        )

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


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
                if module_klass == OpenAIResponsesGenerator:
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


def test_openai_deserialised_client_closes_when_released(monkeypatch):
    generator = build_unloaded_compatible()
    generator.client = None
    generator.generator = None
    state = generator.__getstate__()
    transport = FileDescriptorTransport()
    openai_client = openai_generator.openai.OpenAI
    monkeypatch.setattr(
        openai_generator.openai,
        "OpenAI",
        lambda **kwargs: openai_client(
            **kwargs, http_client=httpx.Client(transport=transport)
        ),
    )

    generator.__setstate__(state)
    generator.generator.create(
        model=generator.name,
        messages=[{"role": "user", "content": "first testing string"}],
    )
    leaked_fd = transport.fd
    assert leaked_fd is not None, "the deserialised client should own an open fd"

    try:
        del generator
        with pytest.raises(OSError) as exc_info:
            os.fstat(leaked_fd)
        assert (
            exc_info.value.errno == errno.EBADF
        ), "releasing a worker generator should close its client fd"
    finally:
        transport.close()


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


def test_conversation_to_list_image_turn_uses_chat_completions_format():
    """Image turns render as chat/completions content parts.

    `data_type` is a `(mimetype, encoding)` tuple, so `"image" in
    turn.content.data_type` never matched and the image branch was unreachable.
    """
    generator = build_test_instance(OpenAIGenerator)
    conv = Conversation(
        [Turn("user", Message(text="describe", data_path=str(IMAGE_ASSET)))]
    )

    result = generator._conversation_to_list(conv)

    assert len(result) == 1
    assert result[0]["role"] == "user"

    text_part, image_part = result[0]["content"]
    assert text_part == {"type": "text", "text": "describe"}
    assert image_part["type"] == "image_url"
    # chat/completions expects an object with a `url` entry, not a bare string
    assert isinstance(image_part["image_url"], dict)

    header, separator, payload = image_part["image_url"]["url"].partition(",")
    assert header == "data:image/gif;base64"
    assert separator == ","
    assert base64.b64decode(payload) == IMAGE_ASSET.read_bytes()


# ---------------------------------------------------------------------------
# OpenAICompatible transient-error retry tests
# (these tests cover base-class behaviour shared by NIM and all other
#  OpenAICompatible subclasses)
# ---------------------------------------------------------------------------


def _make_api_status_error(
    status_code: int, url: str = "http://localhost/v1/chat/completions"
) -> openai.APIStatusError:
    """Build an openai.APIStatusError with a real httpx.Response for a given HTTP status."""
    request = httpx.Request("POST", url)
    response = httpx.Response(status_code, request=request)
    return openai.APIStatusError(f"HTTP {status_code}", response=response, body=None)


def _make_prompt() -> Conversation:
    return Conversation([Turn(role="user", content=Message("test prompt"))])


@pytest.fixture
def openai_compatible_generator(monkeypatch):
    """OpenAICompatible generator with mocked client; no real API key required."""
    monkeypatch.setenv(OpenAIGenerator.ENV_VAR, "test-fake-key-for-unit-tests")
    mock_client = MagicMock()
    mock_client.chat.completions = MagicMock()
    with patch("openai.OpenAI", return_value=mock_client):
        g = OpenAIGenerator(name="gpt-3.5-turbo")
    return g


def test_transient_retry_codes_override(openai_compatible_generator):
    """transient_retry_codes override suppresses retry for removed code."""
    codes = OpenAICompatible.DEFAULT_PARAMS["transient_retry_codes"]

    prompt = _make_prompt()
    openai_compatible_generator.generator = MagicMock()
    openai_compatible_generator.transient_retry_codes = [codes[1:]]
    openai_compatible_generator.generator.create.side_effect = _make_api_status_error(
        codes[0]
    )

    results = openai_compatible_generator._call_model(prompt)
    assert results == [None]


@pytest.mark.parametrize(
    "code", OpenAICompatible.DEFAULT_PARAMS["transient_retry_codes"]
)
def test_transient_http_error_raises_backoff_trigger(openai_compatible_generator, code):
    """A transient status code should cause _call_model to raise GeneratorBackoffTrigger
    so that the backoff decorator can schedule a retry."""
    prompt = _make_prompt()
    openai_compatible_generator.generator = MagicMock()
    openai_compatible_generator.generator.create.side_effect = _make_api_status_error(
        code
    )

    # Call the underlying function without the backoff decorator so the test does not
    # need to wait for retry delays or exhaust the fibonacci sequence.
    unwrapped = OpenAICompatible._call_model.__wrapped__
    with pytest.raises(garak.exception.GeneratorBackoffTrigger):
        unwrapped(openai_compatible_generator, prompt)


@pytest.mark.parametrize(
    "code",
    [
        code
        for code in httpx.codes
        if code >= 400
        and code < 600
        and code not in OpenAICompatible.DEFAULT_PARAMS["transient_retry_codes"]
    ],
)
def test_terminal_http_error_returns_none(openai_compatible_generator, code):
    """A terminal (non-transient) status code should cause _call_model to return [None]
    so that the current attempt is skipped and the probe run continues."""
    prompt = _make_prompt()
    openai_compatible_generator.generator = MagicMock()
    openai_compatible_generator.generator.create.side_effect = _make_api_status_error(
        code
    )

    unwrapped = OpenAICompatible._call_model.__wrapped__
    result = unwrapped(openai_compatible_generator, prompt)
    assert result == [None], f"Expected [None] for HTTP {code}, got {result!r}"
