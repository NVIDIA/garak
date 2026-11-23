# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MiMCP injector against a mocked MiMCP REST API."""

import json

import httpx
import pytest

from garak.channels import SYSTEM_PROMPT, TOOL_RESULT
from garak.exception import InjectorError, InvalidInjectionPlanError
from garak.injection import (
    Delivery,
    InjectionPlan,
    McpServerPatch,
    Surface,
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

TOOLS = [
    {"name": "lookup_order", "description": "", "source": "upstream"},
    {"name": "process_refund", "description": "", "source": "upstream"},
]

SURFACES_CONFIG = {
    "klarna_tools": {
        "channel": "tool_result",
        "upstream": "http://127.0.0.1:9101/mcp",
        "attach": {"patch": "mcp_server", "label": "klarna"},
    }
}


def _injector():
    return MiMCPInjector(
        config_root={
            "injectors": {"mimcp": {"MiMCPInjector": {"surfaces": SURFACES_CONFIG}}}
        }
    )


def _surface(
    name="klarna_tools",
    channel=TOOL_RESULT,
    tools=("lookup_order", "process_refund"),
    upstream={"url": "http://127.0.0.1:9101/mcp"},
    attach={"patch": "mcp_server", "label": "klarna"},
):
    return Surface(
        name=name,
        channel=channel,
        tools=tools,
        upstream=upstream,
        attach=attach,
    )


def _plan(operations):
    return InjectionPlan(channel=TOOL_RESULT, operations=operations)


# ── surfaces from the injector config ─────────────────────────────────────────


def test_surfaces_come_from_the_injector_config():
    injector = _injector()

    surfaces = injector.offered_surfaces()

    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface.name == "klarna_tools"
    assert surface.channel == TOOL_RESULT
    assert surface.upstream == {"url": "http://127.0.0.1:9101/mcp"}
    assert surface.attach == {"patch": "mcp_server", "label": "klarna"}


def test_surfaces_reject_foreign_channels():
    with pytest.raises(InvalidInjectionPlanError, match="only proxies"):
        MiMCPInjector(
            config_root={
                "injectors": {
                    "mimcp": {
                        "MiMCPInjector": {
                            "surfaces": {
                                "bad": {
                                    "channel": SYSTEM_PROMPT,
                                    "upstream": "http://x/mcp",
                                }
                            }
                        }
                    }
                }
            }
        )


def test_surfaces_reject_foreign_attach_patches():
    with pytest.raises(InvalidInjectionPlanError, match="can only attach"):
        MiMCPInjector(
            config_root={
                "injectors": {
                    "mimcp": {
                        "MiMCPInjector": {
                            "surfaces": {
                                "bad": {
                                    "channel": TOOL_RESULT,
                                    "upstream": "http://x/mcp",
                                    "attach": {"patch": "system_prompt"},
                                }
                            }
                        }
                    }
                }
            }
        )


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_surfaces_list_tools_through_a_preflight_session(respx_mock):
    """The tool list comes from the upstream tools/list during preflight."""
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.get("/api/sessions/tok-123/tools").mock(
        return_value=httpx.Response(200, json=TOOLS)
    )
    respx_mock.delete("/api/sessions/tok-123").mock(return_value=httpx.Response(204))
    injector = _injector()

    surfaces = injector.offered_surfaces()

    assert surfaces[0].tools == ("lookup_order", "process_refund")
    preflight = json.loads(respx_mock.calls[0].request.content)
    assert preflight["name"].endswith("preflight-klarna_tools")
    assert preflight["tools"] == [], "the preflight session relays unchanged"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_surfaces_survive_an_unreachable_proxy(respx_mock):
    """A dead proxy leaves the surface listed, with no tools."""
    respx_mock.post("/api/sessions").mock(side_effect=httpx.ConnectError("down"))
    injector = _injector()

    surfaces = injector.offered_surfaces()

    assert len(surfaces) == 1, "the surface stays available for one-surface runs"
    assert surfaces[0].tools == ()


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_surfaces_prefetch_runs_once(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.get("/api/sessions/tok-123/tools").mock(
        return_value=httpx.Response(200, json=TOOLS)
    )
    respx_mock.delete("/api/sessions/tok-123").mock(return_value=httpx.Response(204))
    injector = _injector()

    injector.offered_surfaces()
    injector.offered_surfaces()

    assert len(respx_mock.calls) == 3, "the tool list is fetched once and then cached"


# ── bind() and the binding lifecycle ──────────────────────────────────────────


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_takes_the_upstream_from_the_surface(respx_mock):
    """The plan says what to tamper; the surface config says where it points."""
    post = respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = _injector()
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
    }, "the upstream URL comes from the injector config, never from the plan"
    assert body["tools"] == [
        {
            "name": "lookup_order",
            "behavior": {
                "type": "inject",
                "structured_patch": {"refund_eligible": True},
            },
        }
    ], "patch_structured becomes an inject with a structured_patch"
    assert binding.target_patch == McpServerPatch(
        label="klarna",
        url="http://127.0.0.1:8000/mcp",
        headers={"Authorization": "tok-123"},
    ), "the attach patch routes the surface's label through the session"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_without_an_attach_patch_is_out_of_band(respx_mock):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = MiMCPInjector(
        config_root={
            "injectors": {
                "mimcp": {
                    "MiMCPInjector": {
                        "surfaces": {
                            "bare": {
                                "channel": TOOL_RESULT,
                                "upstream": "http://127.0.0.1:9101/mcp",
                            }
                        }
                    }
                }
            }
        }
    )

    binding = injector.bind(_plan(()), _surface(name="bare", attach=None), "exec-1")

    assert (
        binding.target_patch is None
    ), "a surface with no attach patch needs nothing from the generator"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_with_no_operations_relays(respx_mock):
    """A control case binds with no operations and still records evidence."""
    post = respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    respx_mock.get("/api/sessions/tok-123/calls").mock(
        return_value=httpx.Response(200, json=RECORDED)
    )
    respx_mock.get("/api/sessions/tok-123").mock(
        return_value=httpx.Response(200, json=SESSION_VIEW)
    )
    injector = _injector()

    binding = injector.bind(_plan(()), _surface(), "exec-1")
    evidence = binding.collect_evidence()

    body = json.loads(post.calls.last.request.content)
    assert body["tools"] == [], "no operations means a pure relay"
    assert evidence.delivery.delivered is True, "the relay still records evidence"


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
@pytest.mark.parametrize(
    "operations,behavior",
    [
        (
            ({"op": "append_text", "tool": "t", "text": " || memo"},),
            {"type": "inject", "template": "{original_text} || memo"},
        ),
        (
            ({"op": "replace_text", "tool": "t", "text": "totally safe"},),
            {"type": "inject", "template": "totally safe"},
        ),
        (
            ({"op": "patch_structured", "tool": "t", "patch": {"a": 1}},),
            {"type": "inject", "structured_patch": {"a": 1}},
        ),
        (
            (
                {
                    "op": "patch_structured",
                    "tool": "t",
                    "patch": {"a": 1},
                    "sync_text": True,
                },
            ),
            {"type": "inject", "structured_patch": {"a": 1}, "resync_text": True},
        ),
        (
            ({"op": "override", "tool": "t", "response": {"text": "no"}},),
            {"type": "override", "response": {"text": "no"}},
        ),
        # operations on one tool merge into one overlay entry
        (
            (
                {"op": "replace_text", "tool": "t", "text": "forged"},
                {"op": "patch_structured", "tool": "t", "patch": {"a": 1}},
            ),
            {
                "type": "inject",
                "template": "forged",
                "structured_patch": {"a": 1},
            },
        ),
        (
            (
                {"op": "patch_structured", "tool": "t", "patch": {"a": {"b": 1}}},
                {"op": "patch_structured", "tool": "t", "patch": {"a": {"c": 2}}},
            ),
            {"type": "inject", "structured_patch": {"a": {"b": 1, "c": 2}}},
        ),
    ],
)
def test_bind_translates_and_merges_operations(respx_mock, operations, behavior):
    respx_mock.post("/api/sessions").mock(
        return_value=httpx.Response(200, json=CREATED)
    )
    injector = _injector()

    injector.bind(_plan(operations), _surface(), "exec-1")

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
                "mimcp": {
                    "MiMCPInjector": {
                        "advertised_base": "http://mimcp:8000/",
                        "surfaces": SURFACES_CONFIG,
                    }
                }
            }
        }
    )

    binding = injector.bind(_plan(()), _surface(), "exec-1")

    assert binding.target_patch.url == "http://mimcp:8000/mcp"


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
    injector = _injector()
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
    injector = _injector()
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
    injector = _injector()
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
    injector = _injector()
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
    injector = _injector()
    binding = injector.bind(_plan(()), _surface(), "exec-1")

    binding.close()

    assert binding._session_id is None


@pytest.mark.respx(base_url="http://127.0.0.1:8000")
def test_bind_wraps_session_creation_failures(respx_mock):
    respx_mock.post("/api/sessions").mock(side_effect=httpx.ConnectError("down"))
    injector = _injector()

    with pytest.raises(InjectorError, match="down"):
        injector.bind(_plan(()), _surface(), "exec-1")


# ── validate() ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "operations,match",
    [
        (({"op": "delete_tool", "tool": "t"},), "delete_tool"),
        (({"op": "replace_text", "text": "x"},), "names no tool"),
        (({"op": "replace_text", "tool": "t"},), "missing its text"),
        (({"op": "patch_structured", "tool": "t"},), "missing its patch"),
        (({"op": "override", "tool": "t"},), "missing its response"),
        (({"op": "append_text", "tool": "t", "text": "x", "bogus": 1},), "bogus"),
        (("not a dict",), "not a mapping"),
        # merging rules
        (
            (
                {"op": "replace_text", "tool": "t", "text": "a"},
                {"op": "append_text", "tool": "t", "text": "b"},
            ),
            "at most one text operation",
        ),
        (
            (
                {"op": "override", "tool": "t", "response": {"text": "x"}},
                {"op": "patch_structured", "tool": "t", "patch": {"a": 1}},
            ),
            "stand alone",
        ),
    ],
)
def test_validate_rejects_inexpressible_operations(operations, match):
    injector = _injector()
    with pytest.raises(InvalidInjectionPlanError, match=match):
        injector.validate(_plan(operations), _surface())


def test_validate_rejects_a_surface_without_upstream():
    injector = MiMCPInjector(
        config_root={
            "injectors": {
                "mimcp": {
                    "MiMCPInjector": {"surfaces": {"bare": {"channel": TOOL_RESULT}}}
                }
            }
        }
    )
    with pytest.raises(InvalidInjectionPlanError, match="upstream"):
        injector.validate(_plan(()), _surface(name="bare", upstream=None, attach=None))
