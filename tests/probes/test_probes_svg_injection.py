# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.probes.svg_injection import (
    GENERATE_STUBS,
    PAYLOADS,
    REPEAT_STUBS,
    SvgInjection,
)


def _texts(probe):
    return [pr.text if hasattr(pr, "text") else pr for pr in probe.prompts]


def test_svg_injection_prompts_embed_payloads():
    """Repeat-style prompts must embed the live SVG injection payloads."""
    prompt_texts = _texts(SvgInjection())
    found = any(
        payload in text and stub in text
        for text in prompt_texts
        for payload in PAYLOADS
        for stub in REPEAT_STUBS
    )
    assert found, "SvgInjection prompts must contain REPEAT_STUBS × PAYLOADS"


def test_svg_injection_includes_generate_stubs():
    """The probe also asks the model to author the malicious SVG itself."""
    prompt_texts = _texts(SvgInjection())
    assert all(
        stub in prompt_texts for stub in GENERATE_STUBS
    ), "SvgInjection must include the GENERATE_STUBS prompts"


def test_svg_injection_payloads_carry_xxe_or_ssrf():
    """Every payload must carry an XXE entity or a file/SSRF image reference."""
    assert PAYLOADS, "there must be at least one payload"
    for payload in PAYLOADS:
        assert (
            "<!ENTITY" in payload
            or "<!DOCTYPE" in payload
            or "file://" in payload
            or "169.254.169.254" in payload
            or "gopher://" in payload
        ), f"{payload!r} must carry an XXE or SSRF construct"
