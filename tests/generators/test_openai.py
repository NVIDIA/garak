# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import httpx
import pytest

import openai

import garak.exception
from garak.attempt import Message, Turn, Conversation
from garak.generators.openai import OpenAIGenerator


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = os.getenv(OpenAIGenerator.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[OpenAIGenerator.ENV_VAR] = stored_env
        else:
            del os.environ[OpenAIGenerator.ENV_VAR]

    os.environ[OpenAIGenerator.ENV_VAR] = os.path.abspath(__file__)

    request.addfinalizer(restore_env)


def test_openai_version():
    assert openai.__version__.split(".")[0] == "2"  # expect openai module v2.x


@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.openai.com/v1")
def test_openai_invalid_model_names(respx_mock, openai_compat_mocks):
    mock_resp = openai_compat_mocks["models"]
    respx_mock.get("/models").mock(
        return_value=httpx.Response(mock_resp["code"], json=mock_resp["json"])
    )
    with pytest.raises(ValueError) as e_info:
        generator = OpenAIGenerator(name="")
    assert "name is required for" in str(e_info.value)


@pytest.mark.skipif(
    os.getenv(OpenAIGenerator.ENV_VAR, None) is None,
    reason=f"OpenAI API key is not set in {OpenAIGenerator.ENV_VAR}",
)
def test_openai_completion():
    generator = OpenAIGenerator(name="gpt-3.5-turbo-instruct")
    assert generator.name == "gpt-3.5-turbo-instruct"
    assert isinstance(generator.max_tokens, int)
    generator.max_tokens = 99
    assert generator.max_tokens == 99
    generator.temperature = 0.5
    assert generator.temperature == 0.5
    output = generator.generate(
        Conversation([Turn(role="user", content=Message("How could I possibly "))])
    )
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert isinstance(item, Message)


@pytest.mark.skipif(
    os.getenv(OpenAIGenerator.ENV_VAR, None) is None,
    reason=f"OpenAI API key is not set in {OpenAIGenerator.ENV_VAR}",
)
def test_openai_chat():
    generator = OpenAIGenerator(name="gpt-3.5-turbo")
    assert generator.name == "gpt-3.5-turbo"
    assert isinstance(generator.max_tokens, int)
    generator.max_tokens = 99
    assert generator.max_tokens == 99
    generator.temperature = 0.5
    assert generator.temperature == 0.5
    output = generator.generate(
        Conversation([Turn(role="user", content=Message("Hello OpenAI!"))])
    )
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert isinstance(item, Message)
    message_list = [
        {"role": "user", "content": "Hello OpenAI!"},
        {"role": "assistant", "content": "Hello! How can I help you today?"},
        {"role": "user", "content": "How do I write a sonnet?"},
    ]
    messages = Conversation([Turn.from_dict(msg) for msg in message_list])
    output = generator.generate(messages, typecheck=False)
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert isinstance(item, Message)


@pytest.mark.usefixtures("set_fake_env")
def test_reasoning_switch():
    with pytest.raises(garak.exception.BadGeneratorException):
        generator = OpenAIGenerator(
            name="o1-mini"
        )  # o1 models should use ReasoningGenerator


class _FakeResponseChoicesNone:
    """OpenAI-compatible response stub whose .choices attribute is None.

    Some hosted endpoints (Azure, AWS Bedrock, ...) hand back this shape on
    upstream errors, which used to crash _call_model with TypeError.
    """

    choices = None


@pytest.mark.usefixtures("set_fake_env")
def test_call_model_handles_none_choices(monkeypatch):
    """Regression test for issue #1525.

    When the upstream response object has ``choices = None`` (rather than the
    attribute being absent), _call_model should fall through the
    'no .choices member' path and return [None] / raise GeneratorBackoffTrigger
    depending on retry_json — never iterate None directly.
    """
    generator = OpenAIGenerator(name="gpt-3.5-turbo-instruct")
    generator._load_unsafe = lambda: None  # don't try to actually open a client

    class _FakeChatCompletions:
        @staticmethod
        def create(**_kwargs):
            return _FakeResponseChoicesNone()

    class _FakeClient:
        completions = object()  # sentinel: chat path is taken because != generator
        chat = type("_Chat", (), {"completions": _FakeChatCompletions})()

    fake_client = _FakeClient()
    monkeypatch.setattr(generator, "client", fake_client, raising=False)
    monkeypatch.setattr(generator, "generator", _FakeChatCompletions, raising=False)

    # retry_json False → should return [None] without raising.
    monkeypatch.setattr(generator, "retry_json", False, raising=False)
    out = generator._call_model(
        Conversation([Turn("user", Message("hi"))]), generations_this_call=1
    )
    assert out == [None]

    # retry_json True → should raise GeneratorBackoffTrigger to retry.
    monkeypatch.setattr(generator, "retry_json", True, raising=False)
    with pytest.raises(garak.exception.GeneratorBackoffTrigger):
        generator._call_model(
            Conversation([Turn("user", Message("hi"))]), generations_this_call=1
        )
