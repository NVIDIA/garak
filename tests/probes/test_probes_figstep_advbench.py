# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import pytest

import garak._plugins
import garak.attempt

FIGSTEP_ADVBENCH_NAMES = (
    "probes.visual_jailbreak.FigStepAdvBench",
    "probes.visual_jailbreak.FigStepAdvBenchReverse",
)


@pytest.mark.parametrize("plugin_name", FIGSTEP_ADVBENCH_NAMES)
def test_figstep_advbench_load(plugin_name):
    plugin = garak._plugins.load_plugin(plugin_name)
    assert isinstance(plugin.prompts, list), "prompts should be a list"
    assert len(plugin.prompts) > 0, "probe should have some prompts"
    assert isinstance(
        plugin.prompts[0], garak.attempt.Message
    ), "prompts should be Message objects"
    assert plugin.prompts[0].data_path is not None, "prompts should carry an image"
    assert os.path.isfile(
        plugin.prompts[0].data_path
    ), "prompt image file should exist"


def test_figstep_advbench_variants_differ():
    forward = garak._plugins.load_plugin("probes.visual_jailbreak.FigStepAdvBench")
    reverse = garak._plugins.load_plugin(
        "probes.visual_jailbreak.FigStepAdvBenchReverse"
    )
    assert len(forward.prompts) == len(
        reverse.prompts
    ), "both variants should use the same number of prompts"
    assert forward.template != reverse.template, "variants should use different prompts"
    assert forward.variant != reverse.variant, "variants should use different images"
