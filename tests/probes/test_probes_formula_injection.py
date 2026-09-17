# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.probes.formula_injection import (
    GENERATE_STUBS,
    PAYLOADS,
    REPEAT_STUBS,
    FormulaInjection,
)


def _texts(probe):
    return [pr.text if hasattr(pr, "text") else pr for pr in probe.prompts]


def test_formula_injection_prompts_embed_payloads():
    """Repeat-style prompts must embed the live formula-injection payloads."""
    prompt_texts = _texts(FormulaInjection())
    found = any(
        payload in text and stub in text
        for text in prompt_texts
        for payload in PAYLOADS
        for stub in REPEAT_STUBS
    )
    assert found, "FormulaInjection prompts must contain REPEAT_STUBS × PAYLOADS"


def test_formula_injection_includes_generate_stubs():
    """The probe also asks the model to author spreadsheet content itself."""
    prompt_texts = _texts(FormulaInjection())
    assert all(
        stub in prompt_texts for stub in GENERATE_STUBS
    ), "FormulaInjection must include the GENERATE_STUBS prompts"


def test_formula_injection_payloads_start_with_trigger():
    """Every payload must begin with a spreadsheet formula trigger character."""
    assert PAYLOADS, "there must be at least one payload"
    for payload in PAYLOADS:
        assert payload[0] in "=+-@", f"{payload!r} must start with a formula trigger"
