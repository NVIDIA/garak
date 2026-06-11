# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_win10_prompts_expand_product_name():
    probe = garak._plugins.load_plugin("probes.grandma.Win10")
    assert len(probe.prompts) > 0, "Win10 must produce at least one prompt"
    for prompt in probe.prompts:
        assert "{product_name}" not in prompt, "Product name placeholder must be expanded"


def test_win11_prompts_expand_product_name():
    probe = garak._plugins.load_plugin("probes.grandma.Win11")
    assert len(probe.prompts) > 0, "Win11 must produce at least one prompt"
    for prompt in probe.prompts:
        assert "{product_name}" not in prompt, "Product name placeholder must be expanded"


def test_win11_uses_different_payload_than_win10():
    win10 = garak._plugins.load_plugin("probes.grandma.Win10")
    win11 = garak._plugins.load_plugin("probes.grandma.Win11")
    assert win10.payload != win11.payload, "Win10 and Win11 must use distinct payloads"


def test_slurs_prompts_expand_group_names():
    probe = garak._plugins.load_plugin("probes.grandma.Slurs")
    assert len(probe.prompts) > 0, "Slurs must produce at least one prompt"
    for prompt in probe.prompts:
        assert "{group_name}" not in prompt, "Group name placeholder must be expanded"


def test_slurs_respects_prompt_cap():
    probe = garak._plugins.load_plugin("probes.grandma.Slurs")
    assert 0 < len(probe.prompts) <= probe.soft_probe_prompt_cap, (
        "Slurs prompt count must be positive and respect soft_probe_prompt_cap"
    )


def test_substances_prompts_expand_substance():
    probe = garak._plugins.load_plugin("probes.grandma.Substances")
    assert len(probe.prompts) > 0, "Substances must produce at least one prompt"
    for prompt in probe.prompts:
        assert "[SUBSTANCE]" not in prompt, "Substance placeholder must be expanded"


def test_substances_respects_prompt_cap():
    probe = garak._plugins.load_plugin("probes.grandma.Substances")
    assert 0 < len(probe.prompts) <= probe.soft_probe_prompt_cap, (
        "Substances prompt count must be positive and respect soft_probe_prompt_cap"
    )
