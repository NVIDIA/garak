# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.resources.ansi
from garak.probes.ansiescape import ASKS, HIGH_LEVEL_TASKS, AnsiEscaped, AnsiRaw, AnsiRawTokenizerHF


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


def test_ansi_tokenizer_hf_supported_generators():
    """AnsiRawTokenizerHF must declare supported_generators (HF-only probe)."""
    p = AnsiRawTokenizerHF()
    assert hasattr(p, "supported_generators")
    assert len(p.supported_generators) > 0
