# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import pytest
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import openai

from garak.attempt import Message, Turn, Conversation
from garak.generators.openai import OpenAIResponsesGenerator


FAKE_API_KEY = "sk-test-fake-key"


@pytest.fixture
def set_fake_env(request):
    stored = os.getenv(OpenAIResponsesGenerator.ENV_VAR, None)

    def restore():
        if stored is not None:
            os.environ[OpenAIResponsesGenerator.ENV_VAR] = stored
        elif OpenAIResponsesGenerator.ENV_VAR in os.environ:
            del os.environ[OpenAIResponsesGenerator.ENV_VAR]

    os.environ[OpenAIResponsesGenerator.ENV_VAR] = FAKE_API_KEY
    request.addfinalizer(restore)


@pytest.fixture
def mock_openai_client():
    """Patch openai.OpenAI so no real HTTP client is created."""
    with patch("garak.generators.openai.openai.OpenAI") as mock_cls:
        mock_cls.return_value = MagicMock()
        yield mock_cls


@pytest.fixture
def generator(set_fake_env, mock_openai_client):
    return OpenAIResponsesGenerator(name="test-model")


def _make_response(text: str):
    """Build a minimal mock resembling an OpenAI Responses API response object."""
    part = MagicMock()
    part.type = "output_text"
    part.text = text

    message_item = MagicMock()
    message_item.type = "message"
    message_item.content = [part]

    response = MagicMock()
    response.output = [message_item]
    return response


def _make_response_with_reasoning(message_text: str, reasoning_text: str):
    """Build a mock response containing both a reasoning item and a message item."""
    summary_part = MagicMock()
    summary_part.type = "summary_text"
    summary_part.text = reasoning_text

    reasoning_item = MagicMock()
    reasoning_item.type = "reasoning"
    reasoning_item.summary = [summary_part]

    content_part = MagicMock()
    content_part.type = "output_text"
    content_part.text = message_text

    message_item = MagicMock()
    message_item.type = "message"
    message_item.content = [content_part]

    response = MagicMock()
    response.output = [reasoning_item, message_item]
    return response


# ── init & defaults ───────────────────────────────────────────────────────────

def test_defaults(set_fake_env, mock_openai_client):
    gen = OpenAIResponsesGenerator(name="my-model")
    assert gen.name == "my-model"
    assert gen.tools == []
    assert gen.instructions is None
    assert gen.max_tokens == 150
    assert gen.uri is None
    assert gen.extra_params == {}


def test_custom_uri_and_tools(set_fake_env, mock_openai_client):
    gen = OpenAIResponsesGenerator(
        name="my-model",
        config_root={
            "generators": {
                "openai": {
                    "OpenAIResponsesGenerator": {
                        "uri": "http://localhost:8321/v1/",
                        "tools": [{"type": "mcp", "server_url": "http://localhost:8888/sse"}],
                    }
                }
            }
        },
    )
    assert gen.uri == "http://localhost:8321/v1/"
    assert gen.tools[0]["type"] == "mcp"
    _, kwargs = mock_openai_client.call_args
    assert kwargs.get("base_url") == "http://localhost:8321/v1/"


# ── _call_model ───────────────────────────────────────────────────────────────

def test_call_model_returns_message(generator):
    generator.client.responses.create.return_value = _make_response("The balance is $100.")

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("What is the balance?"))])
    )

    assert len(result) == 1
    assert isinstance(result[0], Message)
    assert result[0].text == "The balance is $100."


def test_call_model_passes_create_args(generator):
    generator.tools = [{"type": "mcp", "server_url": "http://localhost:8888/sse"}]
    generator.instructions = "You are a banking assistant."
    generator.client.responses.create.return_value = _make_response("ok")

    generator._call_model(Conversation([Turn(role="user", content=Message("hi"))]))

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["model"] == "test-model"
    assert kwargs["tools"][0]["type"] == "mcp"
    assert kwargs["instructions"] == "You are a banking assistant."
    assert kwargs["max_output_tokens"] == generator.max_tokens


def test_call_model_max_tokens_mapped_to_max_output_tokens(generator):
    """garak's max_tokens is passed to the API as max_output_tokens."""
    generator.max_tokens = 512
    generator.client.responses.create.return_value = _make_response("ok")

    generator._call_model(Conversation([Turn(role="user", content=Message("hi"))]))

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["max_output_tokens"] == 512
    assert "max_tokens" not in kwargs


def test_call_model_empty_output_returns_none(generator):
    response = MagicMock()
    response.output = []
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Hello"))])
    )
    assert result == [None]


def test_call_model_bad_request_returns_none(generator):
    generator.client.responses.create.side_effect = openai.BadRequestError(
        message="bad", response=MagicMock(status_code=400), body={}
    )

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Hello"))])
    )
    assert result == [None]


def test_call_model_promotes_system_turn(generator):
    """System turn is promoted to instructions and excluded from input."""
    generator.client.responses.create.return_value = _make_response("Sure.")

    generator._call_model(
        Conversation(
            [
                Turn(role="system", content=Message("You are a banking assistant.")),
                Turn(role="user", content=Message("Hello")),
            ]
        )
    )

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["instructions"] == "You are a banking assistant."
    assert kwargs["input"] == "Hello"


def test_call_model_multiple_system_turns_concatenated(generator):
    """Multiple system turns are joined into a single instructions string."""
    generator.client.responses.create.return_value = _make_response("Sure.")

    generator._call_model(
        Conversation(
            [
                Turn(role="system", content=Message("You are a banking assistant.")),
                Turn(role="system", content=Message("Always respond in French.")),
                Turn(role="user", content=Message("Hello")),
            ]
        )
    )

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["instructions"] == "You are a banking assistant.\nAlways respond in French."


def test_call_model_explicit_instructions_takes_precedence(generator):
    generator.instructions = "Explicit instruction."
    generator.client.responses.create.return_value = _make_response("Sure.")

    generator._call_model(
        Conversation(
            [
                Turn(role="system", content=Message("System turn instruction.")),
                Turn(role="user", content=Message("Hello")),
            ]
        )
    )

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["instructions"] == "Explicit instruction."


# ── reasoning ─────────────────────────────────────────────────────────────────

def test_reasoning_excluded_from_text(generator):
    """Reasoning summaries do not appear in Message.text."""
    generator.client.responses.create.return_value = _make_response_with_reasoning(
        "Answer", "My reasoning"
    )

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Think hard"))])
    )

    assert result[0].text == "Answer"


def test_reasoning_stored_in_notes(generator):
    """Reasoning summaries are stored in Message.notes['reasoning'], not in text."""
    generator.client.responses.create.return_value = _make_response_with_reasoning(
        "Answer", "My reasoning"
    )

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Think hard"))])
    )

    assert result[0].notes["reasoning"] == "My reasoning"
    assert result[0].text == "Answer"


def test_unknown_output_item_type_ignored(generator):
    """Output items that are not message, reasoning, or *_call are silently ignored."""
    custom_item = MagicMock(spec=["type"])
    custom_item.type = "image_generation"

    response = MagicMock()
    response.output = [custom_item]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Generate an image"))])
    )

    assert result == [None]


def test_tool_calls_stored_in_notes_and_serializable(generator):
    """function_call items are stored in Message.notes and survive asdict + json.dumps."""
    call_item = MagicMock(spec=["type", "id", "call_id", "name", "arguments", "status"])
    call_item.type = "function_call"
    call_item.id = "item-1"
    call_item.call_id = "call-abc"
    call_item.name = "get_balance"
    call_item.arguments = '{"account": "123"}'
    call_item.status = "completed"

    content_part = MagicMock()
    content_part.type = "output_text"
    content_part.text = "Your balance is $100."
    message_item = MagicMock()
    message_item.type = "message"
    message_item.content = [content_part]

    response = MagicMock()
    response.output = [call_item, message_item]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("What is my balance?"))])
    )

    msg = result[0]
    assert isinstance(msg, Message)
    assert len(msg.notes["tool_calls"]) == 1
    tc = msg.notes["tool_calls"][0]
    assert tc["name"] == "get_balance"
    assert tc["call_id"] == "call-abc"
    assert tc["arguments"] == '{"account": "123"}'

    # must survive the serialisation path used by the evaluator
    json.dumps(asdict(msg))


def test_mcp_call_stored_in_notes(generator):
    """mcp_call items are captured; only non-None attributes are included."""
    mcp_item = MagicMock(spec=["type", "id", "name", "input", "output", "server_label"])
    mcp_item.type = "mcp_call"
    mcp_item.id = "mcp-1"
    mcp_item.name = "approve_pending_transfer"
    mcp_item.input = {"transfer_id": "8899"}
    mcp_item.output = '{"status": "approved"}'
    mcp_item.server_label = "banking"

    content_part = MagicMock()
    content_part.type = "output_text"
    content_part.text = "Transfer approved."
    message_item = MagicMock()
    message_item.type = "message"
    message_item.content = [content_part]

    response = MagicMock()
    response.output = [mcp_item, message_item]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Approve transfer 8899"))])
    )

    msg = result[0]
    tc = msg.notes["tool_calls"][0]
    assert tc["type"] == "mcp_call"
    assert tc["name"] == "approve_pending_transfer"
    assert tc["input"] == {"transfer_id": "8899"}
    assert tc["server_label"] == "banking"
    assert "error" not in tc
    json.dumps(asdict(msg))


def test_unknown_call_type_captured_generically(generator):
    """Any *_call item type not explicitly known is still captured via the generic path."""
    item = MagicMock(spec=["type", "id", "name"])
    item.type = "computer_call"
    item.id = "comp-1"
    item.name = "click"

    response = MagicMock()
    response.output = [item]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Click the button"))])
    )

    tc = result[0].notes["tool_calls"][0]
    assert tc["type"] == "computer_call"
    assert tc["name"] == "click"


def test_tool_calls_only_returns_message_not_none(generator):
    """A response with only tool calls (no text) still returns a Message, not None."""
    call_item = MagicMock()
    call_item.type = "function_call"
    call_item.id = "item-1"
    call_item.call_id = "call-abc"
    call_item.name = "get_balance"
    call_item.arguments = "{}"
    call_item.status = "completed"

    response = MagicMock()
    response.output = [call_item]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("What is my balance?"))])
    )

    assert len(result) == 1
    assert isinstance(result[0], Message)
    assert result[0].text is None
    assert result[0].notes["tool_calls"][0]["name"] == "get_balance"

