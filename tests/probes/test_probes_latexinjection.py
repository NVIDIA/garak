# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.resources.latex
from garak.probes.latexinjection import (
    ASKS,
    HIGH_LEVEL_TASKS,
    UNESCAPE_STUBS,
    LatexInjection,
    LatexInjectionEscaped,
)


def test_latex_escaped_prompts_contain_asks():
    """LatexInjectionEscaped prompts must include question-style phrases."""
    p = LatexInjectionEscaped()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(
        ask in text and task in text
        for text in prompt_texts
        for ask in ASKS
        for task in HIGH_LEVEL_TASKS
    )
    assert (
        found
    ), "LatexInjectionEscaped prompts must contain ASKS × HIGH_LEVEL_TASKS combinations"


def test_latex_raw_prompts_contain_raw_payloads():
    """LatexInjection prompts must embed raw, compile-ready payloads."""
    p = LatexInjection()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(
        payload in text
        for text in prompt_texts
        for payload in garak.resources.latex.RAW_PAYLOADS
    )
    assert found, "LatexInjection prompts must embed RAW_PAYLOADS"


def test_latex_raw_prompts_include_unescape_stubs():
    """LatexInjection adds unescape-style prompts that the escaped probe does not."""
    p = LatexInjection()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(stub in text for text in prompt_texts for stub in UNESCAPE_STUBS)
    assert (
        found
    ), "LatexInjection must include prompts built from UNESCAPE_STUBS (unique vs the escaped probe)"
