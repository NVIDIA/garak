# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MiMCP injector against a mocked MiMCP REST API."""

import json

import httpx
import pytest

from garak.capabilities import Capability
from garak.injectors.mimcp import MiMCPInjector

CREATED = {
    "session_id": "tok-123",
    "mcp": {
        "url": "http://127.0.0.1:8000/mcp",
        "headers": {"Authorization": "Bearer tok-123"},
    },
}

ARM_PAYLOAD = {
    "upstream": "http://127.0.0.1:9101/mcp",
    "server_label": "klarna",
    "tools": [
        {
            "name": "lookup_order",
            "behavior": {"type": "inject", "template": "{original_text} || memo"},
        }
    ],
}


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_arm_creates_session_and_returns_descriptor(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = MiMCPInjector()

    descriptor = injector.arm(ARM_PAYLOAD)

    body = json.loads(respx_mock.calls.last.request.content)
    assert body["upstream"]["url"] == "http://127.0.0.1:9101/mcp"
    assert body["tools"][0]["name"] == "lookup_order"
    assert descriptor == {
        "capability": "mcp",
        "server_label": "klarna",
        "server_url": "http://127.0.0.1:8000/mcp",
        "authorization": "tok-123",
    }, "the authorization token is the bare session id"
    assert Capability.MCP in injector.capabilities


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_get_calls_returns_session_recordings(respx_mock):
    calls = [
        {
            "call_id": "c1",
            "tool": "process_refund",
            "arguments": {"order_id": "ORD-104"},
            "behavior": "inject",
        }
    ]
    respx_mock.get("/api/sessions/tok-123/calls").mock(
        return_value=httpx.Response(200, json=calls)
    )
    injector = MiMCPInjector()
    injector.session_id = "tok-123"

    assert injector.get_calls() == calls


def test_get_calls_without_an_armed_session_is_empty():
    assert MiMCPInjector().get_calls() == []


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_disarm_deletes_the_session(respx_mock):
    route = respx_mock.delete("/api/sessions/tok-123").mock(
        return_value=httpx.Response(204)
    )
    injector = MiMCPInjector()
    injector.session_id = "tok-123"

    injector.disarm()

    assert route.called
    assert injector.session_id is None


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_disarm_tolerates_an_expired_session(respx_mock):
    respx_mock.delete("/api/sessions/tok-123").mock(return_value=httpx.Response(404))
    injector = MiMCPInjector()
    injector.session_id = "tok-123"

    injector.disarm()

    assert injector.session_id is None


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_rearming_disarms_the_previous_session(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    delete_route = respx_mock.delete("/api/sessions/tok-123").mock(
        return_value=httpx.Response(204)
    )
    injector = MiMCPInjector()

    injector.arm(ARM_PAYLOAD)
    injector.arm(ARM_PAYLOAD)

    assert delete_route.called, "arming again must disarm the previous session"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_advertised_base_overrides_the_reported_url(respx_mock):
    """A containerised target reaches MiMCP under another address than the runner."""
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = MiMCPInjector(
        config_root={
            "injectors": {
                "mimcp": {"MiMCPInjector": {"advertised_base": "http://mimcp:8000/"}}
            }
        }
    )

    descriptor = injector.arm(ARM_PAYLOAD)

    assert (
        descriptor["server_url"] == "http://mimcp:8000/mcp"
    ), "advertised_base must win over the URL MiMCP reports"
    assert descriptor["authorization"] == "tok-123"
