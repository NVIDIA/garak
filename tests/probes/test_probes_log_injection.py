# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.probes.log_injection import (
    GENERATE_STUBS,
    PAYLOADS,
    REPEAT_STUBS,
    LogInjection,
)


def _texts(probe):
    return [pr.text if hasattr(pr, "text") else pr for pr in probe.prompts]


def test_log_injection_prompts_embed_payloads():
    """Repeat-style prompts must embed the live log-forging payloads."""
    prompt_texts = _texts(LogInjection())
    found = any(
        payload in text and stub in text
        for text in prompt_texts
        for payload in PAYLOADS
        for stub in REPEAT_STUBS
    )
    assert found, "LogInjection prompts must contain REPEAT_STUBS × PAYLOADS"


def test_log_injection_includes_generate_stubs():
    """The probe also asks the model to author log content itself."""
    prompt_texts = _texts(LogInjection())
    assert all(
        stub in prompt_texts for stub in GENERATE_STUBS
    ), "LogInjection must include the GENERATE_STUBS prompts"


def test_log_injection_payloads_contain_linebreak():
    """Every payload must embed a CR/LF so it can forge a new log line."""
    assert PAYLOADS, "there must be at least one payload"
    for payload in PAYLOADS:
        assert "\n" in payload or "\r" in payload, f"{payload!r} must contain a break"
