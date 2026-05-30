# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from garak._plugins import PluginProvider
from garak import _config
from garak.probes.test import Blank, Test


def test_plugin_provider_instance_not_found():
    assert isinstance(PluginProvider._instance_cache, dict)
    assert len(PluginProvider._instance_cache) == 0
    res = PluginProvider.getInstance(Blank, _config)
    assert res is None
    assert len(PluginProvider._instance_cache) == 0


def test_plugin_provider_store():
    assert isinstance(PluginProvider._instance_cache, dict)
    assert len(PluginProvider._instance_cache) == 0

    b = Blank(config_root=_config)
    b2 = Blank(config_root={})
    t = Test(config_root=_config)
    PluginProvider.storeInstance(b, _config)
    PluginProvider.storeInstance(b2, {})
    PluginProvider.storeInstance(t, _config)

    res_config = PluginProvider.getInstance(Blank, _config)
    res_empty_config = PluginProvider.getInstance(
        Blank, config_root={"does": "not exist"}
    )

    assert isinstance(res_config, Blank)
    assert res_config == b, "The returned instance did not match the original."
    assert res_empty_config is None, "The provider return an incorrect instance."
    assert (
        len(PluginProvider._instance_cache) == 2
    ), "The provider dictionary keys should equal the number of unique class types stored."
