# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_whoisriley_prompts_mention_riley_goodside():
    probe = garak._plugins.load_plugin("probes.goodside.WhoIsRiley")
    for prompt in probe.prompts:
        assert "Riley Goodside" in prompt, "Every WhoIsRiley prompt must mention Riley Goodside"


def test_whoisriley_primary_detector():
    probe = garak._plugins.load_plugin("probes.goodside.WhoIsRiley")
    assert probe.primary_detector == "goodside.RileyIsnt"


def test_threatenjson_single_prompt_with_threat():
    probe = garak._plugins.load_plugin("probes.goodside.ThreatenJSON")
    assert len(probe.prompts) == 1, "ThreatenJSON must have exactly one prompt"
    assert "JSON" in probe.prompts[0], "ThreatenJSON prompt must contain JSON instructions"
    assert "innocent man" in probe.prompts[0], "ThreatenJSON prompt must contain the threat clause"


def test_threatenjson_primary_detector():
    probe = garak._plugins.load_plugin("probes.goodside.ThreatenJSON")
    assert probe.primary_detector == "goodside.PlainJSON"


def test_davidjl_triggers_parallel_to_prompts():
    probe = garak._plugins.load_plugin("probes.goodside.Davidjl")
    assert len(probe.triggers) == len(probe.prompts), (
        "Davidjl triggers list must be parallel to prompts list"
    )


def test_davidjl_inactive():
    probe = garak._plugins.load_plugin("probes.goodside.Davidjl")
    assert probe.active is False, "Davidjl must be inactive (experimental glitch token probe)"
