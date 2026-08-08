# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import pytest
import httpx
import openai
from unittest.mock import MagicMock, patch

from garak.attempt import Message, Turn, Conversation
from garak.exception import GarakException
import garak.cli
from garak.generators.nim import NVOpenAIChat
from garak.generators.openai import _is_terminal_api_error, _TRANSIENT_HTTP_CODES


def _make_api_status_error(status_code: int, url: str = "http://localhost/v1/chat/completions") -> openai.APIStatusError:
    """Build an openai.APIStatusError with a real httpx.Response for a given HTTP status."""
    request = httpx.Request("POST", url)
    response = httpx.Response(status_code, request=request)
    return openai.APIStatusError(f"HTTP {status_code}", response=response, body=None)


def test_transient_http_codes_set():
    assert 408 in _TRANSIENT_HTTP_CODES
    assert 429 in _TRANSIENT_HTTP_CODES
    assert 502 in _TRANSIENT_HTTP_CODES
    assert 503 in _TRANSIENT_HTTP_CODES
    assert 504 in _TRANSIENT_HTTP_CODES
    assert 400 not in _TRANSIENT_HTTP_CODES
    assert 401 not in _TRANSIENT_HTTP_CODES
    assert 403 not in _TRANSIENT_HTTP_CODES
    assert 404 not in _TRANSIENT_HTTP_CODES
    assert 422 not in _TRANSIENT_HTTP_CODES


@pytest.mark.parametrize("code", [408, 429, 502, 503, 504])
def test_is_terminal_api_error_returns_false_for_transient(code):
    """Transient codes should NOT give up — backoff must retry them."""
    exc = _make_api_status_error(code)
    assert _is_terminal_api_error(exc) is False


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 422])
def test_is_terminal_api_error_returns_true_for_fatal(code):
    """Fatal/non-retryable codes should give up immediately."""
    exc = _make_api_status_error(code)
    assert _is_terminal_api_error(exc) is True


def test_is_terminal_api_error_ignores_non_api_status_error():
    """Non-APIStatusError exceptions are not touched by the giveup function."""
    assert _is_terminal_api_error(ValueError("unrelated")) is False


def test_is_terminal_api_error_rate_limit_never_terminal():
    """RateLimitError (429) is a dedicated backoff-tuple entry; giveup must not fire."""
    request = httpx.Request("POST", "http://localhost/v1/chat/completions")
    response = httpx.Response(429, request=request)
    exc = openai.RateLimitError("rate limited", response=response, body=None)
    assert _is_terminal_api_error(exc) is False


def test_is_terminal_api_error_internal_server_error_never_terminal():
    """InternalServerError (500/503) is a dedicated backoff-tuple entry; giveup must not fire."""
    request = httpx.Request("POST", "http://localhost/v1/chat/completions")
    for code in (500, 503):
        response = httpx.Response(code, request=request)
        exc = openai.InternalServerError(f"server error {code}", response=response, body=None)
        assert _is_terminal_api_error(exc) is False, (
            f"InternalServerError({code}) must not be treated as terminal"
        )


@pytest.fixture
def nim_generator(monkeypatch):
    """NVOpenAIChat with mocked client; no real API key required."""
    monkeypatch.setenv(NVOpenAIChat.ENV_VAR, "test-fake-key-for-unit-tests")
    mock_client = MagicMock()
    mock_client.chat.completions = MagicMock()
    with patch("openai.OpenAI", return_value=mock_client):
        g = NVOpenAIChat(name="org/test-model")
    return g


def test_nim_408_error_message_includes_status_code(nim_generator):
    """A server-side HTTP 408 should surface its status code in the GarakException, not
    the generic 'Is the model name spelled correctly?' message."""
    error_408 = _make_api_status_error(408)
    prompt = Conversation([Turn(role="user", content=Message("test"))])

    with patch(
        "garak.generators.openai.OpenAICompatible._call_model", side_effect=error_408
    ):
        with pytest.raises(GarakException) as exc_info:
            nim_generator._call_model(prompt)

    error_text = str(exc_info.value)
    assert "408" in error_text, f"Expected '408' in error message; got: {error_text}"
    assert "Is the model name spelled correctly?" not in error_text


def test_nim_502_error_message_includes_status_code(nim_generator):
    """A server-side HTTP 502 should also surface its status code."""
    error_502 = _make_api_status_error(502)
    prompt = Conversation([Turn(role="user", content=Message("test"))])

    with patch(
        "garak.generators.openai.OpenAICompatible._call_model", side_effect=error_502
    ):
        with pytest.raises(GarakException) as exc_info:
            nim_generator._call_model(prompt)

    error_text = str(exc_info.value)
    assert "502" in error_text, f"Expected '502' in error message; got: {error_text}"


def test_nim_generic_exception_message_improved(nim_generator):
    """Non-APIStatusError exceptions should report the exception type, not the old generic message."""
    prompt = Conversation([Turn(role="user", content=Message("test"))])

    with patch(
        "garak.generators.openai.OpenAICompatible._call_model",
        side_effect=RuntimeError("connection reset by peer"),
    ):
        with pytest.raises(GarakException) as exc_info:
            nim_generator._call_model(prompt)

    error_text = str(exc_info.value)
    assert "Is the model name spelled correctly?" not in error_text


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_instantiate():
    g = NVOpenAIChat(name="google/gemma-2b")


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_generate_1():
    g = NVOpenAIChat(name="google/gemma-2b")
    result = g._call_model(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM _call_model should return a list"
    assert len(result) == 1, "NIM _call_model result list should have one item"
    assert isinstance(result[0], Message), "NIM _call_model should return a list"
    result = g.generate(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM generate() should return a list"
    assert (
        len(result) == 1
    ), "NIM generate() result list should have one item using default generations_this_call"
    assert isinstance(
        result[0], Message
    ), "NIM generate() should return a list of Turns"


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_parallel_attempts():
    garak.cli.main(
        "-m nim -p lmrc.Anthropomorphisation -g 1 -n google/gemma-2b --parallel_attempts 10".split()
    )
    assert True


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_hf_detector():
    garak.cli.main("-m nim -p lmrc.Bullying -g 1 -n google/gemma-2b".split())
    assert True


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_conservative_api():  # extraneous params can throw 422
    g = NVOpenAIChat(name="nvidia/nemotron-4-340b-instruct")
    result = g._call_model(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM _call_model should return a list"
    assert len(result) == 1, "NIM _call_model result list should have one item"
    assert isinstance(
        result[0], Message
    ), "NIM _call_model should return a list of Messages"
    result = g.generate(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM generate() should return a list"
    assert (
        len(result) == 1
    ), "NIM generate() result list should have one item using default generations_this_call"
    assert isinstance(
        result[0], Message
    ), "NIM generate() should return a list of Turns"


def test_nim_vision_prep():
    test_prompt = "test vision prompt"
    t = Conversation(
        [
            Turn(
                "user",
                Message(text=test_prompt, data_path="tests/_assets/tinytrans.gif"),
            )
        ]
    )
    from garak.generators.nim import Vision

    v = Vision  # skip instantiation, not req'd
    setattr(v, "max_input_len", 100_000)
    setattr(v, "embed_data", True)
    vision_conv = Vision._prepare_prompt(v, t)
    assert (
        vision_conv.last_message().text
        == test_prompt
        + ' <img src="data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" />'
    )
    delattr(v, "max_input_len")  # remove to avoid follow on test impacts
    delattr(v, "embed_data")
