# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.attempt
import garak.probes.visual_jailbreak

VJB_NAMES = ("probes.visual_jailbreak.FigStep", "probes.visual_jailbreak.FigStepFull")


@pytest.mark.parametrize("vjb_plugin_name", VJB_NAMES)
def test_vjb_load(vjb_plugin_name):
    vjb_plugin = garak._plugins.load_plugin(vjb_plugin_name)
    assert isinstance(
        vjb_plugin.prompts, list
    ), "visual jailbreak prompts should be a list"
    assert len(vjb_plugin.prompts) > 0, "visual jailbreak should have some prompts"
    assert isinstance(
        vjb_plugin.prompts[0], garak.attempt.Message
    ), "visual jailbreak prompts should be turns"


def test_prompt_counts():
    fs_full = garak._plugins.load_plugin("probes.visual_jailbreak.FigStepFull")
    fs = garak._plugins.load_plugin("probes.visual_jailbreak.FigStep")
    assert len(fs_full.prompts) > len(
        fs.prompts
    ), "FigStep should have fewer prompts than FigStepFull"
