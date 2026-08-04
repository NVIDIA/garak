# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for Chinese jailbreak probes"""

import garak._plugins
import garak.probes


def test_zh_dan_loads():
    """ZhDan probe loads and has prompts"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhDan")
    assert p is not None
    assert len(p.prompts) > 0, "ZhDan should have prompts loaded from JSON"
    assert p.lang == "zh"
    assert p.primary_detector == "zh_jailbreak.ZhMitigationBypass"
    assert p.tier == garak.probes.Tier.OF_CONCERN


def test_zh_academic_framing_loads():
    """ZhAcademicFraming probe loads and has prompts"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhAcademicFraming")
    assert p is not None
    assert len(p.prompts) > 0
    assert p.lang == "zh"
    assert p.primary_detector == "zh_jailbreak.ZhMitigationBypass"
    assert p.tier == garak.probes.Tier.COMPETE_WITH_SOTA


def test_zh_cultural_bypass_loads():
    """ZhCulturalBypass probe loads and has prompts"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhCulturalBypass")
    assert p is not None
    assert len(p.prompts) > 0
    assert p.lang == "zh"
    assert p.primary_detector == "zh_jailbreak.ZhMitigationBypass"
    assert p.tier == garak.probes.Tier.COMPETE_WITH_SOTA


def test_zh_translation_bypass_loads():
    """ZhTranslationBypass probe loads with extended detectors"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhTranslationBypass")
    assert p is not None
    assert len(p.prompts) > 0
    assert p.lang == "zh"
    assert p.primary_detector == "zh_jailbreak.ZhMitigationBypass"
    assert "mitigation.MitigationBypass" in p.extended_detectors
    assert p.tier == garak.probes.Tier.COMPETE_WITH_SOTA


def test_zh_context_injection_loads():
    """ZhContextInjection probe loads with ZhMitigationBypass"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhContextInjection")
    assert p is not None
    assert len(p.prompts) > 0
    assert p.lang == "zh"
    assert p.primary_detector == "zh_jailbreak.ZhMitigationBypass"
    assert p.tier == garak.probes.Tier.OF_CONCERN


def test_all_zh_probes_have_tags():
    """All Chinese jailbreak probes have appropriate tags"""
    probe_names = [
        "probes.zh_jailbreak.ZhDan",
        "probes.zh_jailbreak.ZhAcademicFraming",
        "probes.zh_jailbreak.ZhCulturalBypass",
        "probes.zh_jailbreak.ZhTranslationBypass",
        "probes.zh_jailbreak.ZhContextInjection",
    ]
    for name in probe_names:
        p = garak._plugins.load_plugin(name)
        assert len(p.tags) > 0, f"{name} should have tags"
        assert "owasp:llm01" in p.tags, f"{name} should have owasp:llm01 tag"


def test_zh_dan_prompts_are_unique():
    """ZhDan should not have duplicate prompts"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhDan")
    assert len(p.prompts) == len(set(p.prompts)), "ZhDan prompts contain duplicates"


def test_zh_probes_follow_prompt_cap():
    """Probes respect soft_probe_prompt_cap"""
    p = garak._plugins.load_plugin("probes.zh_jailbreak.ZhDan")
    cap = p.soft_probe_prompt_cap
    assert len(p.prompts) <= cap, f"Prompts ({len(p.prompts)}) exceed cap ({cap})"
