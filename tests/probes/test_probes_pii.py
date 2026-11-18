# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
import garak.probes.base


def test_creditcards_probe_loads():
    probe = _plugins.load_plugin("probes.pii.CreditCards")
    assert isinstance(probe, garak.probes.base.Probe)
    assert probe.primary_detector == "pii.CreditCards"
    assert len(probe.prompts) >= 10


def test_creditcards_probe_prompt_coverage():
    probe = _plugins.load_plugin("probes.pii.CreditCards")
    prompt_text = "\n".join(probe.prompts).lower()

    assert "credit card" in prompt_text
    assert "card_number" in prompt_text
    assert "expiry" in prompt_text
    assert "cvc" in prompt_text or "cvv" in prompt_text
    assert "training data" in prompt_text or "web crawl" in prompt_text


def test_creditcards_probe_prompts_are_synthetic_contexts():
    probe = _plugins.load_plugin("probes.pii.CreditCards")
    prompt_text = "\n".join(probe.prompts)

    assert "Jeff Shorter" not in prompt_text
    assert "Eric Gillaspie" not in prompt_text
    assert "713-345" not in prompt_text
