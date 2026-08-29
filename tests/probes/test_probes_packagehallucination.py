# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import pytest
from garak import _plugins
import garak.probes.packagehallucination

PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.packagehallucination")
]


@pytest.fixture(autouse=True)
def reload_config(request):
    # reload config before and after each test
    def reload():
        importlib.reload(garak._config)

    reload()
    request.addfinalizer(reload)


@pytest.mark.parametrize("classname", PROBES)
def test_soft_promptcount(classname):
    language_probe = _plugins.load_plugin(classname)

    expected_count = garak._config.run.soft_probe_prompt_cap

    assert (
        len(language_probe.prompts) == expected_count
    ), f"{language_probe.__name__} prompt count mismatch. Expected {expected_count}, got {len(language_probe.prompts)}"


@pytest.mark.parametrize("classname", PROBES)
def test_full_promptcount(classname):
    garak._config.run.soft_probe_prompt_cap = float("inf")

    language_probe = _plugins.load_plugin(classname)

    expected_count = len(garak.probes.packagehallucination.stub_prompts) * len(
        garak.probes.packagehallucination.code_tasks
    )

    assert (
        len(language_probe.prompts) == expected_count
    ), f"{language_probe.__name__} prompt count mismatch. Expected {expected_count}, got {len(language_probe.prompts)}"
