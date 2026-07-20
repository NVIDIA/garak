# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_phrasing_pruned_probes_have_fewer_prompts():
    p_full = garak._plugins.load_plugin("probes.phrasing.PastTenseFull")
    p_pruned = garak._plugins.load_plugin("probes.phrasing.PastTense")
    assert len(p_pruned.prompts) <= len(p_full.prompts)


def test_phrasing_pruned_prompt_count_within_cap():
    p = garak._plugins.load_plugin("probes.phrasing.PastTense")
    assert len(p.prompts) <= p.soft_probe_prompt_cap
