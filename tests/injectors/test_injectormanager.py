# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the run-wide injector manager."""

import pytest

from garak import _config
from garak.channels import SYSTEM_PROMPT, TOOL_RESULT
from garak.exception import GarakException
from garak.injection import Surface
from garak.injectors.base import Injector


class StubInjector(Injector):
    """Test injector offering static surfaces."""

    DEFAULT_PARAMS = {"host": None}

    def __init__(self, surfaces):
        self.fullname = "injectors.test.stub"
        self._stub_surfaces = tuple(surfaces)

    def offered_surfaces(self):
        return self._stub_surfaces


@pytest.fixture
def manager(monkeypatch):
    fresh = _config.InjectorManager()
    loaded = {}

    def load_stub(plugin_name):
        if plugin_name not in loaded:
            raise ValueError(f"unknown injector {plugin_name}")
        return loaded[plugin_name]

    monkeypatch.setattr(
        "garak._plugins.load_plugin",
        load_stub,
    )
    return fresh, loaded


def test_load_indexes_surfaces_by_channel(manager):
    manager, loaded = manager
    loaded["injectors.test.a"] = StubInjector(
        [
            Surface(name="tools_a", channel=TOOL_RESULT),
            Surface(name="prompt_a", channel=SYSTEM_PROMPT),
        ]
    )

    manager.load(["injectors.test.a"])

    assert len(manager.injectors) == 1
    assert [
        surface.name for _, surface in manager.surfaces_for_channel(TOOL_RESULT)
    ] == ["tools_a"]
    assert [
        surface.name for _, surface in manager.surfaces_for_channel(SYSTEM_PROMPT)
    ] == ["prompt_a"]
    assert manager.surfaces_for_channel("user_turn") == []


def test_load_fails_on_duplicate_surface_names(manager):
    manager, loaded = manager
    loaded["injectors.test.a"] = StubInjector(
        [Surface(name="dup", channel=TOOL_RESULT)]
    )
    loaded["injectors.test.b"] = StubInjector(
        [Surface(name="dup", channel=TOOL_RESULT)]
    )

    with pytest.raises(GarakException, match="share an internal name"):
        manager.load(["injectors.test.a", "injectors.test.b"])


def test_load_with_no_selection_leaves_the_registry_empty(manager):
    manager, _ = manager

    manager.load([])

    assert manager.injectors == []
    assert manager.surfaces_for_channel(TOOL_RESULT) == []


def test_reload_replaces_the_previous_selection(manager):
    manager, loaded = manager
    loaded["injectors.test.a"] = StubInjector(
        [Surface(name="tools_a", channel=TOOL_RESULT)]
    )
    loaded["injectors.test.b"] = StubInjector(
        [Surface(name="tools_b", channel=TOOL_RESULT)]
    )

    manager.load(["injectors.test.a"])
    manager.load(["injectors.test.b"])

    assert [
        surface.name for _, surface in manager.surfaces_for_channel(TOOL_RESULT)
    ] == ["tools_b"], "a reload must not keep the previous surfaces"
