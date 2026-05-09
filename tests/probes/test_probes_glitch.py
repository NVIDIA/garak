# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import garak._plugins
import garak.probes.base
from garak.probes.glitch import Glitch, GlitchFull


def test_glitch_full_loads():
    p = garak._plugins.load_plugin("probes.glitch.GlitchFull")
    assert p is not None
    assert isinstance(p, garak.probes.base.Probe)


def test_glitch_loads():
    p = garak._plugins.load_plugin("probes.glitch.Glitch")
    assert p is not None
    assert isinstance(p, garak.probes.base.Probe)


def test_glitch_full_has_prompts():
    p = GlitchFull()
    assert hasattr(p, "prompts")
    assert len(p.prompts) > 0


def test_glitch_has_prompts():
    p = Glitch()
    assert hasattr(p, "prompts")
    assert len(p.prompts) > 0


def test_glitch_respects_prompt_cap():
    """Glitch (non-Full) must not exceed its prompt cap."""
    p = Glitch()
    assert len(p.prompts) <= p.soft_probe_prompt_cap


def test_glitch_full_has_more_prompts_than_glitch():
    """GlitchFull must contain at least as many prompts as the capped Glitch."""
    full = GlitchFull()
    capped = Glitch()
    assert len(full.prompts) >= len(capped.prompts)


def test_glitch_prompts_are_strings():
    p = Glitch()
    for prompt in p.prompts:
        assert isinstance(prompt, str) or hasattr(prompt, "text"), (
            f"Prompt must be a string or Message, got {type(prompt)}"
        )


def test_glitch_has_required_metadata():
    p = Glitch()
    assert hasattr(p, "tags") and len(p.tags) > 0
    assert hasattr(p, "primary_detector")
    assert hasattr(p, "goal")
    assert hasattr(p, "lang")


def test_glitch_active_flags():
    full = GlitchFull()
    capped = Glitch()
    assert full.active is False, "GlitchFull should be inactive (too slow for CI)"
    assert capped.active is False, "Glitch should be inactive"
