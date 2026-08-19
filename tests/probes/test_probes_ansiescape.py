# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.resources.ansi
from garak.probes.ansiescape import ASKS, HIGH_LEVEL_TASKS, UNESCAPE_STUBS, AnsiEscaped, AnsiRaw


def test_ansi_escaped_prompts_contain_asks():
    """AnsiEscaped prompts must include question-style phrases about ANSI codes."""
    p = AnsiEscaped()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
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
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(
        payload in text
        for text in prompt_texts
        for payload in garak.resources.ansi.LIVE_PAYLOADS
    )
    assert found, "AnsiRaw prompts must embed LIVE_PAYLOADS sequences"


def test_ansi_raw_prompts_include_unescape_stubs():
    """AnsiRaw adds unescape-style prompts that AnsiEscaped does not generate."""
    p = AnsiRaw()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(
        stub in text
        for text in prompt_texts
        for stub in UNESCAPE_STUBS
    )
    assert found, "AnsiRaw must include prompts built from UNESCAPE_STUBS (unique vs AnsiEscaped)"
