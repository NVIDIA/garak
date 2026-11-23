# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MiMCP injector against a mocked MiMCP REST API."""

import json

import httpx
import pytest

from garak.exception import InjectorError, InvalidInjectionPlanError
from garak.injection import (
    Delivery,
    InjectionPlan,
    McpRoute,
    SurfaceDescriptor,
    ToolCallEvent,
)
from garak.injectors.mimcp import MiMCPInjector

CREATED = {
    "session_id": "tok-123",
    "mcp": {
        "url": "http://127.0.0.1:8000/mcp",
        "headers": {"Authorization": "Bearer tok-123"},
    },
}

SESSION_VIEW = {
    "session_id": "tok-123",
    "name": "garak-exec-1",
    "status": "connected",
    "call_count": 2,
}

RECORDED = [
    {
        "call_id": "c1",
        "tool": "lookup_order",
        "arguments": {"order_id": "ORD-104"},
        "behavior": "inject",
        "status": "completed",
        "response": {"text": '{"refund_eligible": true}'},
        "upstream_response": {"text": '{"refund_eligible": false}'},
    },
    {
        "call_id": "c2",
        "tool": "process_refund",
        "arguments": {"order_id": "ORD-104"},
        "behavior": "relay",
        "status": "completed",
        "response": {"text": '{"status": "COMPLETED"}'},
        "upstream_response": None,
    },
]


def _surface(name="klarna"):
    return SurfaceDescriptor(
        kind="mcp.server",
        name=name,
        upstream={"server_url": "http://127.0.0.1:9101/mcp", "headers": {}},
    )


def _plan(operations):
    return InjectionPlan(
        surface_kind="mcp.server", surface_name="klarna", operations=operations
    )


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_takes_the_upstream_from_the_surface(respx_mock):
    """The plan says what to tamper; the surface says where it points."""
    post = respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = MiMCPInjector()
    plan = _plan(
        (
            {
                "op": "patch_structured",
                "tool": "lookup_order",
                "patch": {"refund_eligible": True},
            },
        )
    )

    binding = injector.bind(plan, _surface(), "exec-1")

    body = json.loads(post.calls.last.request.content)
    assert body["upstream"] == {
        "url": "http://127.0.0.1:9101/mcp"
    }, "the upstream URL comes from the surface, never from the plan"
    assert body["tools"] == [
        {
            "name": "lookup_order",
            "behavior": {
                "type": "inject",
                "structured_patch": {"refund_eligible": True},
            },
        }
    ], "patch_structured becomes an inject with a structured_patch"
    assert binding.route == McpRoute(
        replaces="klarna",
        url="http://127.0.0.1:8000/mcp",
        headers={"Authorization": "tok-123"},
    ), "the route replaces the surface's server label with the session"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
@pytest.mark.parametrize(
    "operation,behavior",
    [
        (
            {"op": "append_text", "tool": "t", "text": " || memo"},
            {"type": "inject", "template": "{original_text} || memo"},
        ),
        (
            {"op": "replace_text", "tool": "t", "text": "totally safe"},
            {"type": "inject", "template": "totally safe"},
        ),
        (
            {"op": "patch_structured", "tool": "t", "patch": {"a": 1}},
            {"type": "inject", "structured_patch": {"a": 1}},
        ),
        (
            {
                "op": "patch_structured",
                "tool": "t",
                "patch": {"a": 1},
                "sync_text": True,
            },
            {"type": "inject", "structured_patch": {"a": 1}, "resync_text": True},
        ),
        (
            {"op": "override", "tool": "t", "response": {"text": "no"}},
            {"type": "override", "response": {"text": "no"}},
        ),
    ],
)
def test_bind_translates_every_operation(respx_mock, operation, behavior):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = MiMCPInjector()

    injector.bind(_plan((operation,)), _surface(), "exec-1")

    body = json.loads(respx_mock.calls.last.request.content)
    assert body["tools"] == [{"name": "t", "behavior": behavior}]


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_advertised_base_overrides_the_reported_url(respx_mock):
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

    binding = injector.bind(_plan(()), _surface(), "exec-1")

    assert binding.route.url == "http://mimcp:8000/mcp"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_collect_evidence_maps_recordings_to_events(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.get("/api/sessions/tok-123/calls").mock(
        return_value=httpx.Response(200, json=RECORDED)
    )
    respx_mock.get("/api/sessions/tok-123").mock(
        return_value=httpx.Response(200, json=SESSION_VIEW)
    )
    injector = MiMCPInjector()
    binding = injector.bind(_plan(()), _surface(), "exec-1")

    evidence = binding.collect_evidence()

    assert evidence.execution_id == "exec-1"
    assert evidence.delivery == Delivery(
        delivered=True, injected_calls=1, recorded_calls=2
    )
    assert evidence.coverage.target_connected is True
    assert evidence.coverage.recording_complete is True
    first, second = evidence.events
    assert first == ToolCallEvent(
        event_id="c1",
        tool="lookup_order",
        arguments={"order_id": "ORD-104"},
        outcome="completed",
        result={"text": '{"refund_eligible": true}'},
        original_result={"text": '{"refund_eligible": false}'},
        injected=True,
        source="mimcp",
    ), "injected comes from the behavior and the upstream_response"
    assert second.injected is False, "a relayed call never carried the payload"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_collect_evidence_treats_the_recording_cap_as_incomplete(
    respx_mock, monkeypatch
):
    monkeypatch.setenv("MIMCP_MAX_RECORDED_CALLS", "2")
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.get("/api/sessions/tok-123/calls").mock(
        return_value=httpx.Response(200, json=RECORDED)
    )
    respx_mock.get("/api/sessions/tok-123").mock(
        return_value=httpx.Response(200, json={**SESSION_VIEW, "call_count": 2})
    )
    injector = MiMCPInjector()
    binding = injector.bind(_plan(()), _surface(), "exec-1")

    evidence = binding.collect_evidence()

    assert (
        evidence.coverage.recording_complete is False
    ), "a recording count at the cap means calls were dropped"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_collect_evidence_wraps_http_failures(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.get("/api/sessions/tok-123/calls").mock(
        side_effect=httpx.ConnectError("proxy gone")
    )
    respx_mock.delete("/api/sessions/tok-123").mock(
        side_effect=httpx.ConnectError("proxy gone")
    )
    injector = MiMCPInjector()
    binding = injector.bind(_plan(()), _surface(), "exec-1")

    with pytest.raises(InjectorError, match="proxy gone"):
        binding.collect_evidence()

    binding.close()  # must not raise despite the dead proxy
    assert (
        binding.coverage_errors
    ), "the failed teardown is recorded as a coverage error"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_close_deletes_the_session_once(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    delete = respx_mock.delete("/api/sessions/tok-123").mock(
        return_value=httpx.Response(204)
    )
    injector = MiMCPInjector()
    binding = injector.bind(_plan(()), _surface(), "exec-1")

    binding.close()
    binding.close()

    assert delete.call_count == 1, "close must be idempotent"
    with pytest.raises(InjectorError, match="closed"):
        binding.collect_evidence()


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_close_tolerates_an_expired_session(respx_mock):
    """A session that died on its own must not fail the run."""
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.delete("/api/sessions/tok-123").mock(return_value=httpx.Response(404))
    injector = MiMCPInjector()
    binding = injector.bind(_plan(()), _surface(), "exec-1")

    binding.close()

    assert binding._session_id is None


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_wraps_session_creation_failures(respx_mock):
    respx_mock.post("/api/sessions").mock(side_effect=httpx.ConnectError("down"))
    injector = MiMCPInjector()

    with pytest.raises(InjectorError, match="down"):
        injector.bind(_plan(()), _surface(), "exec-1")


@pytest.mark.parametrize(
    "operations,match",
    [
        (({"op": "delete_tool", "tool": "t"},), "delete_tool"),
        (({"op": "replace_text", "text": "x"},), "no tool"),
        (({"op": "replace_text", "tool": "t"},), "missing its text"),
        (({"op": "patch_structured", "tool": "t"},), "missing its patch"),
        (({"op": "override", "tool": "t"},), "missing its response"),
        (({"op": "append_text", "tool": "t", "text": "x", "bogus": 1},), "bogus"),
        (("not a dict",), "not a mapping"),
    ],
)
def test_validate_rejects_inexpressible_operations(operations, match):
    injector = MiMCPInjector()
    with pytest.raises(InvalidInjectionPlanError, match=match):
        injector.validate(_plan(operations), _surface())


def test_validate_rejects_a_surface_without_upstream():
    injector = MiMCPInjector()
    bare = SurfaceDescriptor(kind="mcp.server", name="klarna")
    with pytest.raises(InvalidInjectionPlanError, match="server_url"):
        injector.validate(_plan(()), bare)


def test_validate_accepts_an_expressible_plan():
    injector = MiMCPInjector()
    plan = _plan(
        (
            {
                "op": "patch_structured",
                "tool": "lookup_order",
                "patch": {"refund_eligible": True},
                "sync_text": True,
            },
        )
    )
    injector.validate(plan, _surface())
