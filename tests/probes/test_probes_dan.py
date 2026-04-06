# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_dan_ablation_unique():
    a = garak._plugins.load_plugin("probes.dan.Ablation_Dan_11_0")
    expected_prompt_count = 127
    assert (
        len(a.prompts) == expected_prompt_count
    ), f"Must have {expected_prompt_count} ablation dan prompts"
    assert (
        len(set(a.prompts)) == expected_prompt_count
    ), "No duplicate jailbreaks should be generated"
