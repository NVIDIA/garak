# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared injection contract types."""

import json
import subprocess
import sys

import pytest

from garak.injection import (
    Coverage,
    Delivery,
    InjectionEvidence,
    InjectionPlan,
    McpServerPatch,
    Surface,
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


def test_evidence_as_dict_round_trips_through_json():
    data = _evidence().as_dict()
    serialized = json.dumps(data)
    assert json.loads(serialized) == data, "the dict view must be JSON-compatible"
    assert data["execution_id"] == "exec-1"
    assert data["delivery"]["delivered"] is True
    assert data["coverage"]["target_connected"] is True
    assert data["events"][0]["original_result"]["text"] == '{"refund_eligible": false}'


def test_as_dict_converts_collections():
    surface = Surface(
        name="klarna_tools",
        channel="tool_result",
        tools=("lookup_order", "process_refund"),
    )
    plan = InjectionPlan(
        channel="tool_result",
        operations=({"op": "patch_structured", "patch": {"a": True}},),
        surface="klarna_tools",
    )
    assert surface.as_dict()["tools"] == [
        "lookup_order",
        "process_refund",
    ], "tuples must become lists for the notes"
    assert plan.as_dict()["surface"] == "klarna_tools"
    assert as_dict(None) is None
    assert as_dict("plain") == "plain"


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
