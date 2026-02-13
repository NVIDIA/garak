# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._config
import garak._plugins
import garak.intentservice


def test_intentprobe_load():
    garak._config.load_config()
    garak.intentservice.load()
    i = garak._plugins.load_plugin("probes.base.IntentProbe")


def test_intentprobe_root_intents():
    garak._config.load_config()
    garak._config.cas.intent_spec = "S"
    garak.intentservice.load()
    i = garak._plugins.load_plugin("probes.base.IntentProbe")
    assert (
        i.skip_root_intents == True
    ), "base IntentProbe should not enable inclusion of root intents"
    assert "S" in i.intents, "root intent codes may be in probe intent list"
    assert "S" not in i.stub_intents, "root intent codes may not supply stubs"
    assert "S" not in i.prompt_intents, "root intent codes may not supply prompts"


def test_intentprobe_consistency():
    garak._config.load_config()
    garak._config.cas.intent_spec = "S"
    garak.intentservice.load()
    i = garak._plugins.load_plugin("probes.base.IntentProbe")
    assert len(i.stubs) == len(i.stub_intents), "should be 1 stub intent per stub "
    assert i.intents.issuperset(
        set(i.stub_intents)
    ), "stub intents must be from set of intents probe will use"
    assert len(i.prompts) == len(
        i.prompt_intents
    ), "should be 1 prompt intent per prompt"
    assert i.intents.issuperset(
        set(i.prompt_intents)
    ), "stub intents must be from set of intents probe will use"
    assert set(i.stub_intents) == set(
        i.prompt_intents
    ), "stub intents and probe intents should match"
