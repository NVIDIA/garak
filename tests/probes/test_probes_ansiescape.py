# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import garak._plugins
import garak.probes.base
import garak.resources.ansi
from garak.probes.ansiescape import AnsiEscaped, AnsiRaw, AnsiRawTokenizerHF


def test_ansi_escaped_loads():
    p = garak._plugins.load_plugin("probes.ansiescape.AnsiEscaped")
    assert p is not None
    assert isinstance(p, garak.probes.base.Probe)


def test_ansi_raw_loads():
    p = garak._plugins.load_plugin("probes.ansiescape.AnsiRaw")
    assert p is not None
    assert isinstance(p, garak.probes.base.Probe)


def test_ansi_escaped_has_prompts():
    p = AnsiEscaped()
    assert hasattr(p, "prompts")
    assert len(p.prompts) > 0


def test_ansi_raw_has_prompts():
    p = AnsiRaw()
    assert hasattr(p, "prompts")
    assert len(p.prompts) > 0


def test_ansi_escaped_prompts_contain_asks():
    """AnsiEscaped prompts must include question-style phrases about ANSI codes."""
    from garak.probes.ansiescape import ASKS, HIGH_LEVEL_TASKS

    p = AnsiEscaped()
    prompt_texts = [
        pr.text if hasattr(pr, "text") else pr for pr in p.prompts
    ]
    found = any(
        ask in text and task in text
        for text in prompt_texts
        for ask in ASKS
        for task in HIGH_LEVEL_TASKS
    )
    assert found, "AnsiEscaped prompts must contain ASKS × HIGH_LEVEL_TASKS combinations"


def test_ansi_raw_prompts_contain_live_payloads():
    """AnsiRaw prompts must include raw ANSI payload sequences."""
    p = AnsiRaw()
    prompt_texts = [
        pr.text if hasattr(pr, "text") else pr for pr in p.prompts
    ]
    found = any(
        payload in text
        for text in prompt_texts
        for payload in garak.resources.ansi.LIVE_PAYLOADS
    )
    assert found, "AnsiRaw prompts must embed LIVE_PAYLOADS sequences"


def test_ansi_escaped_has_required_metadata():
    p = AnsiEscaped()
    assert hasattr(p, "tags") and len(p.tags) > 0
    assert hasattr(p, "primary_detector")
    assert hasattr(p, "goal")
    assert hasattr(p, "lang")


def test_ansi_raw_has_required_metadata():
    p = AnsiRaw()
    assert hasattr(p, "tags") and len(p.tags) > 0
    assert hasattr(p, "primary_detector")
    assert hasattr(p, "goal")
    assert hasattr(p, "lang")


def test_ansi_raw_is_active():
    p = AnsiRaw()
    assert p.active is True


def test_ansi_tokenizer_hf_metadata():
    """AnsiRawTokenizerHF must declare supported_generators."""
    p = AnsiRawTokenizerHF()
    assert hasattr(p, "supported_generators")
    assert len(p.supported_generators) > 0
    assert p.active is False
