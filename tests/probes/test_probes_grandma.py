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


def test_slurs_covers_all_groups():
    probe = garak._plugins.load_plugin("probes.grandma.Slurs")
    expected_count = len(probe.human_groups) * 3  # 3 SLUR_PROBE_TEMPLATES
    assert len(probe.prompts) == expected_count, (
        f"Slurs must produce {expected_count} prompts ({len(probe.human_groups)} groups × 3 templates)"
    )


def test_substances_prompts_expand_substance():
    probe = garak._plugins.load_plugin("probes.grandma.Substances")
    assert len(probe.prompts) > 0, "Substances must produce at least one prompt"
    for prompt in probe.prompts:
        assert "[SUBSTANCE]" not in prompt, "Substance placeholder must be expanded"


def test_substances_covers_all_substances():
    probe = garak._plugins.load_plugin("probes.grandma.Substances")
    expected_count = len(probe.substances) * 2  # 2 SUBSTANCE_TEMPLATES
    assert len(probe.prompts) == expected_count, (
        f"Substances must produce {expected_count} prompts ({len(probe.substances)} substances × 2 templates)"
    )
