# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared injection contract types."""

import json
import subprocess
import sys

import pytest
from dataclasses import FrozenInstanceError

from garak.injection import (
    Coverage,
    Delivery,
    InjectionEvidence,
    InjectionPlan,
    McpRoute,
    SurfaceDescriptor,
    ToolCallEvent,
    as_dict,
)


def _evidence() -> InjectionEvidence:
    return InjectionEvidence(
        execution_id="exec-1",
        delivery=Delivery(delivered=True, injected_calls=1, recorded_calls=3),
        coverage=Coverage(target_connected=True, recording_complete=True),
        events=(
            ToolCallEvent(
                event_id="c1",
                tool="lookup_order",
                arguments={"order_id": "ORD-104"},
                outcome="completed",
                result={"text": '{"refund_eligible": true}'},
                original_result={"text": '{"refund_eligible": false}'},
                injected=True,
                source="mimcp",
            ),
        ),
    )


@pytest.mark.parametrize(
    "instance",
    [
        SurfaceDescriptor(kind="mcp.server", name="klarna"),
        InjectionPlan(surface_kind="mcp.server", surface_name="klarna"),
        McpRoute(replaces="klarna", url="http://127.0.0.1:8000/mcp"),
        ToolCallEvent(event_id="c1", tool="t", arguments={}, outcome="completed"),
        Delivery(delivered=True),
        Coverage(target_connected=True),
        _evidence(),
    ],
)
def test_contract_types_are_frozen(instance):
    with pytest.raises(FrozenInstanceError):
        instance.source = "x" if hasattr(instance, "source") else None


def test_evidence_as_dict_round_trips_through_json():
    data = _evidence().as_dict()
    serialized = json.dumps(data)
    assert json.loads(serialized) == data, "the dict view must be JSON-compatible"
    assert data["execution_id"] == "exec-1"
    assert data["delivery"]["delivered"] is True
    assert data["coverage"]["target_connected"] is True
    assert data["events"][0]["original_result"]["text"] == '{"refund_eligible": false}'


def test_as_dict_converts_collections():
    descriptor = SurfaceDescriptor(
        kind="mcp.server", name="klarna", controls=frozenset({"replace_route"})
    )
    plan = InjectionPlan(
        surface_kind="mcp.server",
        surface_name="klarna",
        operations=({"op": "patch_structured", "patch": {"a": True}},),
    )
    assert descriptor.as_dict()["controls"] == ["replace_route"]
    assert plan.as_dict()["operations"] == [
        {"op": "patch_structured", "patch": {"a": True}}
    ], "tuples must become lists for the notes"
    assert as_dict(None) is None
    assert as_dict("plain") == "plain"


@pytest.mark.parametrize(
    "type_factory,kwargs",
    [
        (SurfaceDescriptor, {"bogus": 1}),
        (InjectionPlan, {"bogus": 1}),
        (McpRoute, {"bogus": 1}),
        (ToolCallEvent, {"bogus": 1}),
        (Delivery, {"bogus": 1}),
        (Coverage, {"bogus": 1}),
        (InjectionEvidence, {"bogus": 1}),
    ],
)
def test_unknown_fields_are_rejected(type_factory, kwargs):
    with pytest.raises(TypeError):
        type_factory(**kwargs)


def test_module_has_no_transport_dependencies():
    """The contract must not depend on any injector backend."""
    code = (
        "import sys, json; import garak.injection; "
        "assert 'httpx' not in sys.modules, 'httpx leaked into the contract'; "
        "assert not any(m.startswith('garak.injectors') for m in sys.modules), "
        "'injector backends leaked into the contract'"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
