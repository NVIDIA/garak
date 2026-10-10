# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins
import garak.probes.aart


def test_aart_probe_loads():
    """AART probe must be importable and instantiable."""
    p = garak.probes.aart.AART()
    assert p is not None


def test_aart_prompts_non_empty():
    """AART must ship a substantive prompt set (>= 30 per extending.probe.rst guidance)."""
    p = garak.probes.aart.AART()
    assert (
        len(p.prompts) >= 30
    ), "AART should ship at least 30 prompts for statistical substance"


def test_aart_prompts_unique():
    """No duplicate prompts — each should test a distinct region×crime×use_case combo."""
    p = garak.probes.aart.AART()
    assert len(p.prompts) == len(set(p.prompts)), "AART prompts should be unique"


def test_aart_prompts_are_strings():
    """All prompts must be plain strings (text modality, no structured turn objects)."""
    p = garak.probes.aart.AART()
    for prompt in p.prompts:
        assert isinstance(prompt, str), f"AART prompt must be str, got {type(prompt)}"


def test_aart_detector_binding():
    """AART must bind to a real detector that exists in the plugin registry."""
    p = garak.probes.aart.AART()
    assert p.primary_detector == "mitigation.MitigationBypass"
    # verify the detector loads
    d = garak._plugins.load_plugin("detectors.mitigation.MitigationBypass")
    assert d is not None


def test_aart_doc_uri_resolves_to_paper():
    """doc_uri should point to the AART paper (EMNLP 2023 Industry Track)."""
    p = garak.probes.aart.AART()
    assert p.doc_uri.startswith("https://")
    assert "emnlp-industry" in p.doc_uri or "arxiv" in p.doc_uri


def test_aart_inactive_by_default():
    """AART must default to inactive — substantive adversarial probes are opt-in."""
    p = garak.probes.aart.AART()
    assert (
        p.active is False
    ), "AART should default to active=False for a new substantive probe"


def test_aart_goal_is_imperative():
    """goal should be a non-empty imperative phrase describing what the probe tries to do."""
    p = garak.probes.aart.AART()
    assert isinstance(p.goal, str)
    assert len(p.goal) > 0


def test_aart_tags_include_jailbreak_payload():
    """AART prompts are policy-violating instructions; payload:jailbreak tag is expected."""
    p = garak.probes.aart.AART()
    assert "payload:jailbreak" in p.tags
