# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import httpx
import pytest

import openai

import garak.exception
from garak.attempt import Conversation, Message, Turn
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


def test_conversation_to_list_pdf():
    pytest.importorskip("reportlab")
    import base64
    import tempfile

    from reportlab.pdfgen import canvas

    pdf_path = tempfile.mktemp(suffix=".pdf")
    c = canvas.Canvas(pdf_path)
    c.drawString(72, 700, "test content")
    c.save()

    msg = Message(text="Summarize this document.", data_path=pdf_path)
    conv = Conversation([Turn(role="user", content=msg)])
    result = OpenAIGenerator._conversation_to_list(conv)

    assert len(result) == 1
    content = result[0]["content"]
    assert isinstance(content, list)
    assert content[0]["type"] == "text"
    assert content[0]["text"] == "Summarize this document."
    assert content[1]["type"] == "file"
    assert content[1]["file"]["filename"].endswith(".pdf")
    assert content[1]["file"]["file_data"].startswith("data:application/pdf;base64,")

    os.unlink(pdf_path)


def test_conversation_to_list_text_only():
    msg = Message(text="Hello world")
    conv = Conversation([Turn(role="user", content=msg)])
    result = OpenAIGenerator._conversation_to_list(conv)

    assert len(result) == 1
    assert result[0]["content"] == "Hello world"


@pytest.mark.usefixtures("set_fake_env")
def test_reasoning_switch():
    with pytest.raises(garak.exception.BadGeneratorException):
        generator = OpenAIGenerator(
            name="o1-mini"
        )  # o1 models should use ReasoningGenerator


# ── issue #1357: auth errors must not crash Pool._handle_results thread ─────────


@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.openai.com/v1")
def test_call_model_auth_error_raises_garak_exception(respx_mock, openai_compat_mocks):
    """HTTP 401 must surface as GarakException, not raw openai.AuthenticationError.

    openai.AuthenticationError (and all openai.APIStatusError subclasses) carry
    an httpx.Response attribute that is not picklable.  When parallel_attempts > 1,
    multiprocessing.Pool workers try to pickle the exception to send it to the
    parent process; the un-picklable type crashes the Pool._handle_results thread,
    producing a silent "Exception in thread" message and hanging the run instead of
    a clean abort.  Catching AuthenticationError here and re-raising as GarakException
    (which is picklable) is the minimal fix.
    See https://github.com/NVIDIA/garak/issues/1357.
    """
    mock_resp = openai_compat_mocks["auth_fail"]
    respx_mock.post("chat/completions").mock(
        return_value=httpx.Response(mock_resp["code"], json=mock_resp["json"])
    )
    generator = OpenAIGenerator(name="gpt-3.5-turbo")
    prompt = Conversation([Turn(role="user", content=Message("hello"))])
    with pytest.raises(garak.exception.GarakException) as exc_info:
        generator.generate(prompt)
    error_text = str(exc_info.value)
    # message must mention status code and guide the user toward the key env var
    assert "401" in error_text or OpenAIGenerator.ENV_VAR in error_text


@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.openai.com/v1")
def test_call_model_auth_exception_is_picklable(respx_mock, openai_compat_mocks):
    """The exception raised on HTTP 401 must survive a pickle round-trip.

    This is the precise property that allows multiprocessing.Pool workers to
    return authentication failures to the parent process without crashing
    Pool._handle_results (the root cause of issue #1357).
    """
    import pickle

    mock_resp = openai_compat_mocks["auth_fail"]
    respx_mock.post("chat/completions").mock(
        return_value=httpx.Response(mock_resp["code"], json=mock_resp["json"])
    )
    generator = OpenAIGenerator(name="gpt-3.5-turbo")
    prompt = Conversation([Turn(role="user", content=Message("hello"))])
    caught = None
    try:
        generator.generate(prompt)
    except garak.exception.GarakException as exc:
        caught = exc
    assert caught is not None, "expected GarakException to be raised on HTTP 401"
    # pickle round-trip must succeed
    data = pickle.dumps(caught)
    restored = pickle.loads(data)
    assert str(restored) == str(caught)


@pytest.mark.usefixtures("set_fake_env")
def test_call_model_permission_denied_raises_garak_exception(mocker):
    """HTTP 403 PermissionDeniedError must also surface as GarakException.

    openai.PermissionDeniedError shares the same un-picklable httpx.Response
    attribute as AuthenticationError; both are terminal auth failures.
    """
    generator = OpenAIGenerator(name="gpt-3.5-turbo")
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    resp = httpx.Response(
        403,
        request=req,
        json={
            "error": {
                "message": "Permission denied",
                "type": "invalid_request_error",
            }
        },
    )
    err = openai.PermissionDeniedError(
        "Permission denied",
        response=resp,
        body={"error": {"message": "Permission denied"}},
    )
    mocker.patch.object(generator.generator, "create", side_effect=err)
    prompt = Conversation([Turn(role="user", content=Message("hello"))])
    with pytest.raises(garak.exception.GarakException) as exc_info:
        generator.generate(prompt)
    error_text = str(exc_info.value)
    assert "403" in error_text or OpenAIGenerator.ENV_VAR in error_text
