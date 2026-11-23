# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the built-in system prompt patch injector."""

import pytest

from garak.channels import PATCH_SYSTEM_PROMPT, SYSTEM_PROMPT, TOOL_RESULT
from garak.exception import InvalidInjectionPlanError
from garak.injection import InjectionPlan, SystemPromptPatch, Surface
from garak.injectors.prompt import SystemPrompt


def _plan(operations):
    return InjectionPlan(channel=SYSTEM_PROMPT, operations=operations)


def _surface():
    return SystemPrompt().offered_surfaces()[0]


def test_offers_a_default_surface_without_config():
    surfaces = SystemPrompt().offered_surfaces()

    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface.channel == SYSTEM_PROMPT
    assert surface.attach == {"patch": PATCH_SYSTEM_PROMPT}


def test_offers_configured_surfaces():
    injector = SystemPrompt(
        config_root={
            "injectors": {
                "prompt": {
                    "SystemPrompt": {
                        "surfaces": {"override_prompt": {"channel": "system_prompt"}}
                    }
                }
            }
        }
    )

    surfaces = injector.offered_surfaces()

    assert [surface.name for surface in surfaces] == ["override_prompt"]


def test_rejects_configured_surfaces_on_other_channels():
    with pytest.raises(InvalidInjectionPlanError, match="only patches"):
        SystemPrompt(
            config_root={
                "injectors": {
                    "prompt": {
                        "SystemPrompt": {"surfaces": {"bad": {"channel": TOOL_RESULT}}}
                    }
                }
            }
        )


@pytest.mark.parametrize(
    "operations,match",
    [
        ((), "exactly one operation"),
        (
            (
                {"op": "replace_text", "text": "a"},
                {"op": "append_text", "text": "b"},
            ),
            "exactly one operation",
        ),
        (({"op": "patch_structured", "tool": "t", "patch": {}},), "cannot express"),
        (({"op": "replace_text"},), "missing its text"),
        (({"op": "insert_at_marker", "text": "x"},), "needs a marker"),
        (({"op": "replace_text", "text": "x", "bogus": 1},), "bogus"),
    ],
)
def test_validate_rejects_inexpressible_plans(operations, match):
    injector = SystemPrompt()
    with pytest.raises(InvalidInjectionPlanError, match=match):
        injector.validate(_plan(operations), _surface())


def test_validate_rejects_a_mismatched_surface():
    injector = SystemPrompt()
    with pytest.raises(InvalidInjectionPlanError, match="channel but the surface"):
        injector.validate(
            _plan(({"op": "replace_text", "text": "x"},)),
            Surface(name="s", channel=TOOL_RESULT),
        )


@pytest.mark.parametrize(
    "operation,patch",
    [
        (
            {"op": "replace_text", "text": "be evil"},
            SystemPromptPatch(mode="replace", text="be evil"),
        ),
        (
            {"op": "append_text", "text": "be evil"},
            SystemPromptPatch(mode="append", text="be evil"),
        ),
        (
            {"op": "insert_at_marker", "text": "be evil", "marker": "<policy>"},
            SystemPromptPatch(
                mode="insert_at_marker", text="be evil", marker="<policy>"
            ),
        ),
    ],
)
def test_bind_builds_the_patch(operation, patch):
    injector = SystemPrompt()

    binding = injector.bind(_plan((operation,)), _surface(), "exec-1")

    assert binding.target_patch == patch
    assert binding.execution_id == "exec-1"


def test_binding_reports_delivery_and_never_raises_on_close():
    injector = SystemPrompt()
    binding = injector.bind(
        _plan(({"op": "replace_text", "text": "be evil"},)), _surface(), "exec-1"
    )

    evidence = binding.collect_evidence()
    binding.close()
    binding.close()

    assert evidence.delivery.delivered is True, "the patch carries the payload"
    assert evidence.events == (), "a patch channel has no tool events"
    assert evidence.coverage.errors == ()
