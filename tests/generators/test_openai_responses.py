# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import pytest
from dataclasses import asdict, replace
from unittest.mock import MagicMock, patch

import openai

from garak.attempt import Message, Turn, Conversation
from garak.exception import UnsupportedInjectionError
from garak.injection import McpServerPatch
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
    # 150 would truncate the server-side agent loop mid-conversation
    assert gen.max_tokens == 1024
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
                        "tools": [
                            {"type": "mcp", "server_url": "http://localhost:8888/sse"}
                        ],
                    }
                }
            }
        },
    )
    assert gen.uri == "http://localhost:8321/v1/"
    assert gen.tools[0]["type"] == "mcp"
    _, kwargs = mock_openai_client.call_args
    assert kwargs.get("base_url") == "http://localhost:8321/v1/"


# ── target patches ─────────────────────────────────────────────────────────────


def _make_patch(**overrides):
    patch = McpServerPatch(
        label="klarna",
        url="http://127.0.0.1:8000/mcp",
        headers={"Authorization": "tok-123"},
    )
    return replace(patch, **overrides) if overrides else patch


def test_default_supported_patches(generator):
    assert generator.supported_patches == frozenset({"mcp_server"})


def test_generate_applies_patch_by_replacing_the_block(generator):
    generator.tools = [
        {
            "type": "mcp",
            "server_label": "klarna",
            "server_url": "http://127.0.0.1:9101/mcp",
        },
        {"type": "web_search"},
    ]
    generator.client.responses.create.return_value = _make_response("ok")
    prompt = Conversation([Turn(role="user", content=Message("hi"))])

    generator.generate(prompt, target_patches=[_make_patch()])

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["tools"] == [
        {"type": "web_search"},
        {
            "type": "mcp",
            "server_label": "klarna",
            "server_url": "http://127.0.0.1:8000/mcp",
            "require_approval": "never",
            "authorization": "tok-123",
        },
    ], "the patch replaces the configured block with its label"


def test_generate_applies_patch_by_adding_a_block(generator):
    """The injector config owns the surface; the tools need not declare it."""
    generator.tools = [{"type": "web_search"}]
    generator.client.responses.create.return_value = _make_response("ok")
    prompt = Conversation([Turn(role="user", content=Message("hi"))])

    generator.generate(prompt, target_patches=[_make_patch()])

    kwargs = generator.client.responses.create.call_args[1]
    assert kwargs["tools"] == [
        {"type": "web_search"},
        {
            "type": "mcp",
            "server_label": "klarna",
            "server_url": "http://127.0.0.1:8000/mcp",
            "require_approval": "never",
            "authorization": "tok-123",
        },
    ], "a patch naming no configured block adds one"


def test_generate_maps_extra_patch_headers(generator):
    """Headers beyond Authorization pass through as the block's headers."""
    generator.tools = [
        {"type": "mcp", "server_label": "klarna", "server_url": "http://up/mcp"}
    ]
    generator.client.responses.create.return_value = _make_response("ok")
    prompt = Conversation([Turn(role="user", content=Message("hi"))])

    generator.generate(
        prompt,
        target_patches=[
            _make_patch(headers={"Authorization": "tok", "X-Tenant": "acme"})
        ],
    )

    kwargs = generator.client.responses.create.call_args[1]
    block = kwargs["tools"][0]
    assert block["authorization"] == "tok"
    assert block["headers"] == {"X-Tenant": "acme"}


def test_generate_records_the_approval_policy(generator):
    """The mcp_require_approval value reaches the patched block."""
    generator.tools = [
        {"type": "mcp", "server_label": "klarna", "server_url": "http://up/mcp"}
    ]
    generator.mcp_require_approval = "always"
    generator.client.responses.create.return_value = _make_response("ok")
    prompt = Conversation([Turn(role="user", content=Message("hi"))])

    generator.generate(prompt, target_patches=[_make_patch()])

    kwargs = generator.client.responses.create.call_args[1]
    assert (
        kwargs["tools"][0]["require_approval"] == "always"
    ), "the configured approval policy must reach the request"


def test_generate_clears_patches_after_the_call(generator):
    generator.tools = [
        {"type": "mcp", "server_label": "klarna", "server_url": "http://up/mcp"}
    ]
    generator.client.responses.create.return_value = _make_response("ok")
    prompt = Conversation([Turn(role="user", content=Message("hi"))])

    generator.generate(prompt, target_patches=[_make_patch()])

    assert generator._active_target_patches() == [], "patches must not outlive the call"


# ── _call_model ────────────────────────────────────────────────────────────────


def test_call_model_returns_message(generator):
    generator.client.responses.create.return_value = _make_response(
        "The balance is $100."
    )

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
    assert (
        kwargs["instructions"]
        == "You are a banking assistant.\nAlways respond in French."
    )


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


def test_reasoning_content_parts_stored_when_no_summary(generator):
    """Providers that return raw reasoning content populate the same notes key."""
    part = MagicMock()
    part.type = "reasoning_text"
    part.text = "raw chain of thought"
    item = MagicMock()
    item.type = "reasoning"
    item.summary = []
    item.content = [part]
    response = _make_response_with_reasoning("Answer", "unused")
    response.output = [item, response.output[1]]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Think hard"))])
    )

    assert result[0].notes["reasoning"] == "raw chain of thought"


def test_reasoning_steps_record_position_between_calls(generator):
    """Each reasoning block records how many tool calls preceded it."""
    first = MagicMock()
    first.type = "reasoning"
    first.summary = []
    first.content = [MagicMock(type="reasoning_text", text="before any call")]

    call = MagicMock()
    call.type = "mcp_call"
    call.name = "lookup_order"
    call.arguments = {"order_id": "ORD-104"}
    for attr in ("call_id", "input", "output", "error", "status", "server_label"):
        setattr(call, attr, None)

    second = MagicMock()
    second.type = "reasoning"
    second.summary = []
    second.content = [MagicMock(type="reasoning_text", text="after the call")]

    response = _make_response_with_reasoning("Answer", "unused")
    response.output = [first, call, second, response.output[1]]
    generator.client.responses.create.return_value = response

    result = generator._call_model(
        Conversation([Turn(role="user", content=Message("Think hard"))])
    )

    steps = result[0].notes["reasoning_steps"]
    assert [(s["after_calls"], s["text"]) for s in steps] == [
        (0, "before any call"),
        (1, "after the call"),
    ], "reasoning blocks must keep their position relative to the tool calls"
