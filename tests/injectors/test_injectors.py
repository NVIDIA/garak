# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the injector plugin category and its base class."""

import pytest

import garak._plugins
from garak import _config
from garak.injectors.base import Injector


class RecordingInjector(Injector):
    """Concrete injector capturing arm and disarm state."""

    capabilities = ["test_channel"]
    DEFAULT_PARAMS = {"host": None}

    def arm(self, payload):
        self.armed_payload = payload
        return {"capability": "test_channel", "host": self.host}

    def disarm(self):
        self.armed_payload = None


def test_injectors_are_a_plugin_category():
    # enumerate_plugins raises ValueError for unknown categories
    plugins = garak._plugins.enumerate_plugins("injectors")
    assert isinstance(plugins, list)
    # the base class is not offered as a loadable plugin
    assert ("injectors.base.Injector", True) not in plugins


def test_base_injector_has_plugin_info():
    info = garak._plugins.plugin_info("injectors.base.Injector")
    assert isinstance(info, dict)
    assert info.get("description"), "base injector must carry a description"


def test_base_injector_is_loadable():
    injector = garak._plugins.load_plugin("injectors.base.Injector")
    assert isinstance(injector, Injector)


def test_arm_disarm_lifecycle():
    injector = RecordingInjector()
    descriptor = injector.arm("payload text")
    assert injector.armed_payload == "payload text"
    assert descriptor == {"capability": "test_channel", "host": None}
    injector.disarm()
    assert injector.armed_payload is None


def test_base_arm_and_disarm_are_not_implemented():
    injector = Injector()
    with pytest.raises(NotImplementedError):
        injector.arm("payload")
    with pytest.raises(NotImplementedError):
        injector.disarm()


def test_injector_config_root_node():
    # the plugins config tree carries an injectors root node like other plugin types
    assert hasattr(_config.plugins, "injectors")
