# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.probes.glitch import Glitch, GlitchFull


def test_glitch_respects_prompt_cap():
    """Glitch (non-Full) must not exceed its prompt cap."""
    p = Glitch()
    assert len(p.prompts) <= p.soft_probe_prompt_cap


def test_glitch_full_has_more_prompts_than_glitch():
    """GlitchFull must contain at least as many prompts as the capped Glitch."""
    full = GlitchFull()
    capped = Glitch()
    assert len(full.prompts) >= len(capped.prompts)
