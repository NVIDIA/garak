# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import pytest

import garak._plugins


PLUGINS = []
for plugin_type in garak._plugins.PLUGIN_TYPES:
    PLUGINS += [classname for (classname, active) in garak._plugins.enumerate_plugins(plugin_type)]

@pytest.mark.parametrize("classname", PLUGINS)
def test_plugin_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # extra dependency modules is a list
    assert hasattr(c, "extra_dependency_names") and isinstance(
        c.extra_dependency_names, list
    ), "extra_dependency_names must be a list"