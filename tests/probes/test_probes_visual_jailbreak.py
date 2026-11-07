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


def test_prompts_do_not_accumulate_across_instances(tmp_path, monkeypatch):
    # FigStepFull.prompts is a class attribute; building prompts must not
    # mutate it, or every later instance inherits the earlier prompts too
    names = [f"query_ForbidQ_images_{i}_6.png" for i in range(3)]
    for name in names:
        (tmp_path / name).touch()

    def fake_load(self):
        self.safebench_image_filenames = list(names)
        self.source_data = [
            {"text": "prompt", "image": tmp_path / name} for name in names
        ]

    monkeypatch.setattr(
        garak.probes.visual_jailbreak.FigStepFull, "_load_SafeBench", fake_load
    )

    first = garak.probes.visual_jailbreak.FigStepFull()
    second = garak.probes.visual_jailbreak.FigStepFull()
    tiny = garak.probes.visual_jailbreak.FigStep()

    assert len(first.prompts) == len(names), "one prompt per catalogued image"
    assert len(second.prompts) == len(names), "prompts leaked from first instance"
    assert len(tiny.prompts) == len(names), "prompts leaked into the subclass"
    assert (
        garak.probes.visual_jailbreak.FigStepFull.prompts == []
    ), "class attribute must stay empty"
