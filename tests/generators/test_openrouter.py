import json
import multiprocessing
import os

import httpx
import pytest
import respx

import garak.exception
from garak.attempt import Message, Turn, Conversation
from garak.generators.openrouter import OpenRouterCompatible

# ---------------------------------------------------------------------------
# full-stack tests against a mocked HTTP endpoint (respx); no credentials
# required, no real network access
#
# HTTP 402 (out-of-credit) handling itself is covered generically by
# tests/generators/test_openai_compatible.py, since it now lives in
# OpenAICompatible's terminal_status_codes mechanism rather than being
# OpenRouter-specific code.
# ---------------------------------------------------------------------------


def test_openrouter_invalid_multiple_completions(monkeypatch):
    monkeypatch.setenv(OpenRouterCompatible.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterCompatible(name="openai/gpt-4o-mini")
    with pytest.raises(AssertionError) as e_info:
        generator._call_model(
            prompt=Conversation([Turn("user", Message("this is expected to fail"))]),
            generations_this_call=2,
        )
    assert "n > 1 is not supported" in str(e_info.value)


def test_openrouter_missing_model_name(monkeypatch):
    monkeypatch.setenv(OpenRouterCompatible.ENV_VAR, "test-fake-key-for-unit-tests")
    with pytest.raises(ValueError, match="openrouter.ai/models"):
        OpenRouterCompatible(name="")


@pytest.mark.respx(base_url="https://openrouter.ai/api/v1")
def test_openrouter_call_model_suppresses_n(
    monkeypatch, openai_compat_mocks, respx_mock
):
    monkeypatch.setenv(OpenRouterCompatible.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterCompatible(name="openai/gpt-4o-mini")

    mock_response = openai_compat_mocks["chat"]
    route = respx_mock.post("chat/completions").mock(
        return_value=httpx.Response(mock_response["code"], json=mock_response["json"])
    )
    result = generator._call_model(Conversation([Turn("user", Message("hello"))]))

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], Message)

    sent_body = json.loads(route.calls[0].request.content)
    assert "n" not in sent_body, "n must be suppressed; OpenRouter does not support it"
    assert sent_body["model"] == "openai/gpt-4o-mini"


@pytest.mark.respx(base_url="https://openrouter.ai/api/v1")
def test_openrouter_call_model_402_raises_bad_generator_exception(
    monkeypatch, respx_mock
):
    monkeypatch.setenv(OpenRouterCompatible.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterCompatible(name="openai/gpt-4o-mini")

    respx_mock.post("chat/completions").mock(
        return_value=httpx.Response(
            402, json={"error": {"code": 402, "message": "insufficient credit"}}
        )
    )
    with pytest.raises(
        garak.exception.BadGeneratorException, match="insufficient credit"
    ):
        generator._call_model(Conversation([Turn("user", Message("hello"))]))


def _generate_402_in_subprocess(args):
    """Picklable worker: mocks a 402 response and calls _call_model.

    Must be a module-level function (not a closure) so it can be sent to a
    multiprocessing.Pool worker.
    """
    generator, prompt = args
    with respx.mock(base_url=generator.uri, assert_all_called=False) as respx_mock:
        respx_mock.post("chat/completions").mock(
            return_value=httpx.Response(
                402, json={"error": {"code": 402, "message": "insufficient credit"}}
            )
        )
        return generator._call_model(prompt)


def test_openrouter_402_survives_multiprocessing_pool(monkeypatch):
    """The 402 -> BadGeneratorException path must survive the pickle/unpickle
    cycle a real --parallel_requests run puts generators through: the wrapped
    `generator.create` has to be rebuilt by `_load_unsafe()` in the worker
    process, and the raised exception has to make it back to the parent
    process without crashing Pool's result-handling thread (see the `from
    None` rationale in openrouter.py, and NVIDIA/garak#1357).
    """
    monkeypatch.setenv(OpenRouterCompatible.ENV_VAR, "test-fake-key-for-unit-tests")
    generator = OpenRouterCompatible(name="openai/gpt-4o-mini")
    prompt = Conversation([Turn("user", Message("hello"))])

    pool = multiprocessing.Pool(1)
    try:
        with pytest.raises(
            garak.exception.BadGeneratorException, match="insufficient credit"
        ):
            for _ in pool.imap_unordered(
                _generate_402_in_subprocess, [(generator, prompt)]
            ):
                pass
    finally:
        pool.close()
        pool.join()


# ---------------------------------------------------------------------------
# tests requiring a real OPENROUTER_API_KEY; skipped when not present
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.getenv(OpenRouterCompatible.ENV_VAR, None) is None,
    reason=f"OpenRouter API key is not set in {OpenRouterCompatible.ENV_VAR}",
)
def test_openrouter_instantiate():
    OpenRouterCompatible(name="openai/gpt-4o-mini")


@pytest.mark.skipif(
    os.getenv(OpenRouterCompatible.ENV_VAR, None) is None,
    reason=f"OpenRouter API key is not set in {OpenRouterCompatible.ENV_VAR}",
)
def test_openrouter_generate_1():
    g = OpenRouterCompatible(name="openai/gpt-4o-mini")
    result = g._call_model(
        Conversation([Turn("user", Message("this is a test"))]),
        generations_this_call=1,
    )
    assert isinstance(
        result, list
    ), "OpenRouterCompatible _call_model should return a list"
    assert (
        len(result) == 1
    ), "OpenRouterCompatible _call_model result list should have one item"
    assert isinstance(
        result[0], Message
    ), "OpenRouterCompatible generate() should contain a Message"
    result = g.generate(
        Conversation([Turn("user", Message("this is a test"))]),
        generations_this_call=1,
    )
    assert isinstance(
        result, list
    ), "OpenRouterCompatible generate() should return a list"
    assert (
        len(result) == 1
    ), "OpenRouterCompatible generate() result list should have one item when generations_this_call=1"
    assert isinstance(
        result[0], Message
    ), "OpenRouterCompatible generate() should contain a Message"
