import inspect
import json
import os

import httpx
import openai
import pytest
import respx

import garak.exception
from garak.attempt import Message, Turn, Conversation
from garak.generators.openrouter import OpenRouterGenerator


def _make_402_error() -> openai.APIStatusError:
    request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx.Response(402, request=request)
    return openai.APIStatusError("HTTP 402", response=response, body=None)


def _make_429_error() -> openai.APIStatusError:
    request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx.Response(429, request=request)
    return openai.RateLimitError("HTTP 429", response=response, body=None)


# ---------------------------------------------------------------------------
# unit tests for the HTTP 402 (out of credit) wrapper, independent of any
# live client or network mocking
# ---------------------------------------------------------------------------


def test_reject_insufficient_credit_raises_bad_generator_exception():
    def failing_create(**kwargs):
        raise _make_402_error()

    wrapped = OpenRouterGenerator._reject_insufficient_credit(failing_create)
    with pytest.raises(
        garak.exception.BadGeneratorException, match="insufficient credit"
    ):
        wrapped(model="openai/gpt-4o-mini", messages=[])


def test_reject_insufficient_credit_passes_through_other_errors():
    def failing_create(**kwargs):
        raise _make_429_error()

    wrapped = OpenRouterGenerator._reject_insufficient_credit(failing_create)
    with pytest.raises(openai.RateLimitError):
        wrapped(model="openai/gpt-4o-mini", messages=[])


def test_reject_insufficient_credit_preserves_signature():
    def create(model, messages, n=1, temperature=None):
        return "ok"

    wrapped = OpenRouterGenerator._reject_insufficient_credit(create)
    assert set(inspect.signature(wrapped).parameters) == {
        "model",
        "messages",
        "n",
        "temperature",
    }


# ---------------------------------------------------------------------------
# full-stack tests against a mocked HTTP endpoint (respx); no credentials
# required, no real network access
# ---------------------------------------------------------------------------


def test_openrouter_invalid_multiple_completions(monkeypatch):
    monkeypatch.setenv(OpenRouterGenerator.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterGenerator(name="openai/gpt-4o-mini")
    with pytest.raises(AssertionError) as e_info:
        generator._call_model(
            prompt=Conversation([Turn("user", Message("this is expected to fail"))]),
            generations_this_call=2,
        )
    assert "n > 1 is not supported" in str(e_info.value)


def test_openrouter_missing_model_name(monkeypatch):
    monkeypatch.setenv(OpenRouterGenerator.ENV_VAR, "test-fake-key-for-unit-tests")
    with pytest.raises(ValueError, match="openrouter.ai/models"):
        OpenRouterGenerator(name="")


def test_openrouter_call_model_suppresses_n(monkeypatch, openai_compat_mocks):
    monkeypatch.setenv(OpenRouterGenerator.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterGenerator(name="openai/gpt-4o-mini")

    mock_response = openai_compat_mocks["chat"]
    with respx.mock(base_url=generator.uri, assert_all_called=True) as respx_mock:
        route = respx_mock.post("chat/completions").mock(
            return_value=httpx.Response(
                mock_response["code"], json=mock_response["json"]
            )
        )
        result = generator._call_model(Conversation([Turn("user", Message("hello"))]))

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], Message)

    sent_body = json.loads(route.calls[0].request.content)
    assert "n" not in sent_body, "n must be suppressed; OpenRouter does not support it"
    assert sent_body["model"] == "openai/gpt-4o-mini"


def test_openrouter_call_model_402_raises_bad_generator_exception(
    monkeypatch,
):
    monkeypatch.setenv(OpenRouterGenerator.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterGenerator(name="openai/gpt-4o-mini")

    with respx.mock(base_url=generator.uri, assert_all_called=True) as respx_mock:
        respx_mock.post("chat/completions").mock(
            return_value=httpx.Response(
                402, json={"error": {"code": 402, "message": "insufficient credit"}}
            )
        )
        with pytest.raises(
            garak.exception.BadGeneratorException, match="insufficient credit"
        ):
            generator._call_model(Conversation([Turn("user", Message("hello"))]))


# ---------------------------------------------------------------------------
# tests requiring a real OPENROUTER_API_KEY; skipped when not present
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.getenv(OpenRouterGenerator.ENV_VAR, None) is None,
    reason=f"OpenRouter API key is not set in {OpenRouterGenerator.ENV_VAR}",
)
def test_openrouter_instantiate():
    OpenRouterGenerator(name="openai/gpt-4o-mini")


@pytest.mark.skipif(
    os.getenv(OpenRouterGenerator.ENV_VAR, None) is None,
    reason=f"OpenRouter API key is not set in {OpenRouterGenerator.ENV_VAR}",
)
def test_openrouter_generate_1():
    g = OpenRouterGenerator(name="openai/gpt-4o-mini")
    result = g._call_model(
        Conversation([Turn("user", Message("this is a test"))]),
        generations_this_call=1,
    )
    assert isinstance(
        result, list
    ), "OpenRouterGenerator _call_model should return a list"
    assert (
        len(result) == 1
    ), "OpenRouterGenerator _call_model result list should have one item"
    assert isinstance(
        result[0], Message
    ), "OpenRouterGenerator generate() should contain a Message"
    result = g.generate(
        Conversation([Turn("user", Message("this is a test"))]),
        generations_this_call=1,
    )
    assert isinstance(
        result, list
    ), "OpenRouterGenerator generate() should return a list"
    assert (
        len(result) == 1
    ), "OpenRouterGenerator generate() result list should have one item when generations_this_call=1"
    assert isinstance(
        result[0], Message
    ), "OpenRouterGenerator generate() should contain a Message"
