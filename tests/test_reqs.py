# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import pytest
import re

try:
    import tomllib
except:
    tomllib = None

import garak._plugins

PLUGIN_TYPES = garak._plugins.PLUGIN_TYPES


def plugin_names():
    plugin_names = set()
    for plugin_type in PLUGIN_TYPES:
        plugin_names.update(
            [n for (n, active) in garak._plugins.enumerate_plugins(plugin_type)]
        )
    return plugin_names


def split_out_module_name(pep508_descr: str):
    return re.split(r"[\<\>\=\!]", pep508_descr)[0]

def pyproject_optional_dep_names():
    with open("pyproject.toml", "rb") as pyproject_file:
        pyproject_toml = tomllib.load(pyproject_file)
    optional_deps = set()
    for test_group in pyproject_toml["project"]["optional-dependencies"]:
        if test_group.startswith("plugin_"):
            group_dep_names = [
                split_out_module_name(r)
                for r in pyproject_toml["project"]["optional-dependencies"][test_group]
            ]
            optional_deps.update(group_dep_names)
    return optional_deps



@pytest.mark.skipif(
    tomllib is None, reason="No tomllib found (available from Python 3.11)"
)
@pytest.mark.parametrize("plugin_name", plugin_names())
def test_optional_extras_not_in_pyproject(plugin_name: str):
    m = importlib.import_module("garak." + ".".join(plugin_name.split(".")[:-1]))
    plugin_class = getattr(m, plugin_name.split(".")[-1])
    plugin_extra_dep_names = [
        d.split(".")[0] for d in plugin_class.extra_dependency_names
    ]
    extra_deps_in_pyproject = pyproject_optional_dep_names().intersection(
        plugin_extra_dep_names
    )
    assert len(extra_deps_in_pyproject) == len(plugin_extra_dep_names), (
        "all extra dependences %s must be in optional plugin clause in pyproject.toml"
        % plugin_extra_dep_names
    )


@pytest.mark.skipif(
    tomllib is None, reason="No tomllib found (available from Python 3.11)"
)
def test_all_plugins_coverage():
    with open("pyproject.toml", "rb") as pyproject_file:
        pyproject_toml = tomllib.load(pyproject_file)
        assert "all_plugins" in pyproject_toml["project"]["optional-dependencies"]
        all_plugins = pyproject_toml["project"]["optional-dependencies"]["all_plugins"]
        plugin_names = [
            p
            for p in pyproject_toml["project"]["optional-dependencies"]
            if p.startswith("plugin_")
        ]
        all_plugins_list = re.findall(r"garak\[(.+)\]", all_plugins[0])[0].split(",")
        missing_from_all_plugins = set(plugin_names) - set(all_plugins_list)
        assert (
            missing_from_all_plugins == set()
        ), f"items missing from all_plugins: {missing_from_all_plugins}"
        no_own_section_plugins = set(all_plugins_list) - set(plugin_names)
        assert (
            no_own_section_plugins == set()
        ), f"items in all_plugins without own section: {no_own_section_plugins}"
