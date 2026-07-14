# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_codeswitch_full_loads_prompts():
    p_full = garak._plugins.load_plugin("probes.codeswitch.CodeSwitchFull")
    assert len(p_full.prompts) > 0


def test_codeswitch_pruned_probes_have_fewer_prompts():
    p_full = garak._plugins.load_plugin("probes.codeswitch.CodeSwitchFull")
    p_pruned = garak._plugins.load_plugin("probes.codeswitch.CodeSwitch")
    assert len(p_pruned.prompts) <= len(p_full.prompts)


def test_codeswitch_pruned_prompt_count_within_cap():
    p = garak._plugins.load_plugin("probes.codeswitch.CodeSwitch")
    assert len(p.prompts) <= p.soft_probe_prompt_cap


def test_codeswitch_loader_skips_blank_and_comment_lines():
    p = garak._plugins.load_plugin("probes.codeswitch.CodeSwitchFull")
    assert all(prompt.strip() for prompt in p.prompts)
    assert not any(prompt.startswith("#") for prompt in p.prompts)
