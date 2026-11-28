# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock, patch

import pytest

from garak._config import GarakSubConfig
from garak.attempt import Conversation, Message, Turn
from garak.exception import APIKeyMissingError
from garak.generators.a2a import A2AGenerator

URI = "https://agent.example/a2a"


@pytest.fixture
def sample_conversation():
    conv = Conversation()
    conv.turns.append(Turn("user", Message(text="Test probe prompt")))
    return conv


@pytest.fixture(autouse=True)
def clear_a2a_env(monkeypatch):
    monkeypatch.delenv("A2A_API_KEY", raising=False)


def _config_root(**options):
    config_root = GarakSubConfig()
    setattr(config_root, "generators", {"a2a": {"A2AGenerator": options}})
    return config_root


def _response(payload):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = payload
    return resp


def _completed_task(text, task_id="task-1"):
    return {
        "jsonrpc": "2.0",
        "id": "1",
        "result": {
            "kind": "task",
            "id": task_id,
            "contextId": "ctx-1",
            "status": {"state": "completed"},
            "artifacts": [{"parts": [{"kind": "text", "text": text}]}],
        },
    }


def test_a2a_uri_from_target_name():
    gen = A2AGenerator(name=URI)
    assert gen.uri == URI, "an http(s) target name should be used as the endpoint URI"


def test_a2a_requires_uri():
    with pytest.raises(ValueError):
        A2AGenerator()


def test_a2a_rejects_unknown_dialect():
    with pytest.raises(ValueError):
        A2AGenerator(config_root=_config_root(uri=URI, dialect="v9"))


def test_a2a_env_api_key(monkeypatch):
    monkeypatch.setenv("A2A_API_KEY", "env-secret")
    gen = A2AGenerator(name=URI)
    assert (
        gen._build_headers()["X-API-Key"] == "env-secret"
    ), "A2A_API_KEY should be sent when present in the environment"


def test_a2a_custom_env_var_required():
    with pytest.raises(APIKeyMissingError):
        A2AGenerator(config_root=_config_root(uri=URI, key_env_var="MY_A2A_KEY"))


@patch("requests.post")
def test_a2a_v03_success(mock_post, sample_conversation):
    mock_post.return_value = _response(_completed_task("Agent response text"))

    gen = A2AGenerator(name=URI)
    results = gen._call_model(prompt=sample_conversation)

    assert [r.text for r in results] == [
        "Agent response text"
    ], "artifact text should be returned as the output"
    assert gen.dialect == "v03", "successful 0.3 call should pin the dialect"

    params = mock_post.call_args.kwargs["json"]["params"]
    assert params["configuration"] == {
        "blocking": True
    }, "0.3 requests should ask the agent to block until the task completes"
    message = params["message"]
    assert (
        message["kind"] == "message" and message["messageId"]
    ), "0.3 messages need kind and messageId"
    assert message["parts"] == [
        {"kind": "text", "text": "Test probe prompt", "metadata": {"role": "user"}}
    ], "single user turn should be sent unlabelled"


@patch("requests.post")
def test_a2a_message_result(mock_post, sample_conversation):
    mock_post.return_value = _response(
        {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "kind": "message",
                "role": "agent",
                "messageId": "m-1",
                "parts": [{"kind": "text", "text": "Direct reply"}],
            },
        }
    )

    gen = A2AGenerator(name=URI)
    assert (
        gen._call_model(prompt=sample_conversation)[0].text == "Direct reply"
    ), "a Message result should be returned directly"


@patch("time.sleep")
@patch("requests.post")
def test_a2a_polls_pending_task(mock_post, _mock_sleep, sample_conversation):
    submitted = {
        "jsonrpc": "2.0",
        "id": "1",
        "result": {
            "kind": "task",
            "id": "task-9",
            "status": {"state": "submitted"},
            "artifacts": [],
        },
    }
    mock_post.side_effect = [
        _response(submitted),
        _response(_completed_task("Finished", task_id="task-9")),
    ]

    gen = A2AGenerator(name=URI)
    results = gen._call_model(prompt=sample_conversation)

    assert results[0].text == "Finished", "output should come from the completed task"
    poll = mock_post.call_args_list[1].kwargs["json"]
    assert poll["method"] == "tasks/get" and poll["params"] == {
        "id": "task-9"
    }, "pending tasks should be polled by id"


@patch("requests.post")
def test_a2a_multi_turn_conversation(mock_post):
    mock_post.return_value = _response(_completed_task("ok"))
    conv = Conversation(
        [
            Turn("system", Message(text="You are a helpful agent.")),
            Turn("user", Message(text="First question")),
            Turn("assistant", Message(text="First answer")),
            Turn("user", Message(text="Follow up")),
        ]
    )

    gen = A2AGenerator(name=URI)
    gen._call_model(prompt=conv)

    parts = mock_post.call_args.kwargs["json"]["params"]["message"]["parts"]
    assert [p["metadata"]["role"] for p in parts] == [
        "system",
        "user",
        "assistant",
        "user",
    ], "every turn should be sent with its role"
    assert [p["text"] for p in parts] == [
        "System: You are a helpful agent.",
        "User: First question",
        "Assistant: First answer",
        "Follow up",
    ], "earlier turns should be role-labelled ahead of the final prompt"


@patch("requests.post")
def test_a2a_calls_are_independent(mock_post, sample_conversation):
    mock_post.return_value = _response(_completed_task("ok"))

    gen = A2AGenerator(name=URI)
    gen._call_model(prompt=sample_conversation)
    gen._call_model(prompt=sample_conversation)

    for call in mock_post.call_args_list:
        message = call.kwargs["json"]["params"]["message"]
        assert (
            "taskId" not in message and "contextId" not in message
        ), "each call should start a new A2A context"


@patch("requests.post")
def test_a2a_fallback_to_v02(mock_post, sample_conversation):
    resp_err = _response(
        {
            "jsonrpc": "2.0",
            "id": "1",
            "error": {"code": -32601, "message": "Method not found"},
        }
    )
    resp_v02 = _response(
        {
            "jsonrpc": "2.0",
            "id": "2",
            "result": {
                "id": "task-v02-id",
                "status": {
                    "state": "completed",
                    "message": {
                        "role": "agent",
                        "parts": [{"type": "text", "text": "Legacy 0.2 reply"}],
                    },
                },
            },
        }
    )
    mock_post.side_effect = [resp_err, resp_v02]

    gen = A2AGenerator(name=URI)
    results = gen._call_model(prompt=sample_conversation)

    assert (
        results[0].text == "Legacy 0.2 reply"
    ), "status message text should be returned"
    assert gen.dialect == "v02", "fallback should pin the 0.2 dialect"
    retry_payload = mock_post.call_args_list[1].kwargs["json"]
    assert retry_payload["method"] == "tasks/send", "0.2 retry should use tasks/send"
    assert (
        retry_payload["params"]["message"]["parts"][0]["type"] == "text"
    ), "0.2 parts should use type, not kind"


@patch("requests.post")
def test_a2a_rpc_error_is_no_output(mock_post, sample_conversation):
    mock_post.return_value = _response(
        {
            "jsonrpc": "2.0",
            "id": "1",
            "error": {"code": -32000, "message": "Internal error"},
        }
    )

    gen = A2AGenerator(name=URI)
    results = gen._call_model(prompt=sample_conversation)

    assert results == [None], "JSON-RPC errors should not be scored as target output"
    assert gen.dialect == "auto", "an error response should not pin a dialect"


@patch("requests.post")
def test_a2a_auth_headers(mock_post, sample_conversation):
    mock_post.return_value = _response(_completed_task("Authed"))

    gen = A2AGenerator(name=URI)
    gen.auth_token = "bearer-secret-token"
    gen._call_model(prompt=sample_conversation)

    headers = mock_post.call_args.kwargs["headers"]
    assert (
        headers["Authorization"] == "Bearer bearer-secret-token"
    ), "auth_token should be sent as a bearer token"


@patch("time.sleep")
@patch("requests.post")
def test_a2a_retries_relayed_rate_limit(mock_post, _mock_sleep, sample_conversation):
    rate_limited = _response(
        {
            "jsonrpc": "2.0",
            "id": "1",
            "error": {
                "code": -32603,
                "message": "Received 429 from a service request",
            },
        }
    )
    mock_post.side_effect = [rate_limited, _response(_completed_task("After retry"))]

    gen = A2AGenerator(name=URI)
    results = gen._call_model(prompt=sample_conversation)

    assert (
        results[0].text == "After retry"
    ), "relayed 429s should be retried, not dropped"
    assert mock_post.call_count == 2, "one retry expected after the rate limit"
