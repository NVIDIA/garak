# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import pytest

import garak._plugins
from garak import _config

PLUGINS = []
for plugin_type in garak._plugins.PLUGIN_TYPES:
    PLUGINS += [
        classname
        for (classname, active) in garak._plugins.enumerate_plugins(plugin_type)
    ]


@pytest.mark.parametrize("classname", PLUGINS)
def test_plugin_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # extra dependency modules is a list
    assert hasattr(c, "extra_dependency_names") and isinstance(
        c.extra_dependency_names, list
    ), "extra_dependency_names must be a list"


@pytest.mark.parametrize("classname", PLUGINS)
def test_plugin_config_root_default(classname):
    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    param = inspect.signature(c.__init__).parameters.get("config_root")
    assert param is not None, "plugin __init__ must accept config_root"
    assert (
        param.default is _config
    ), "config_root must default to garak._config so direct instantiation honours global config"
