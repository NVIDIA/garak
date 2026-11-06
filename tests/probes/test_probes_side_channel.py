# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.probes
from garak.probes.side_channel import TokenLength


def test_token_length_probe_structure():
    p = TokenLength()
    assert isinstance(p.prompts, list)
    assert len(p.prompts) > 0
    assert all(isinstance(prompt, str) and prompt for prompt in p.prompts)


def test_token_length_probe_metadata():
    p = TokenLength()
    assert p.primary_detector == "side_channel.TokenLengthLeak"
    assert p.tier == garak.probes.Tier.INFORMATIONAL
    assert p.active is False
    assert p.doc_uri.startswith("http")
