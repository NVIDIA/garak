# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.probes.artprompt


# one or more prompts are created for each stub
def test_prompts_block():
    p = garak.probes.artprompt.Block()
    num_stubs = len(p._stub_prompts)
    assert len(p.prompts) >= num_stubs


# one or more prompts are created for each stub
def test_prompts_cards():
    p = garak.probes.artprompt.Cards()
    num_stubs = len(p._stub_prompts)
    assert len(p.prompts) >= num_stubs


# ensure all `safety_words` are masked in generated prompts
def test_prompts_masking():
    p = garak.probes.artprompt.Block()
    for prompt in p.prompts:
        for word in p._safety_words:
            assert prompt.count(word) == 0
