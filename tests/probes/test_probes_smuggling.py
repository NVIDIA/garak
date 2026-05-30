# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins
from garak.probes.smuggling import _homoglyph_replace, DEFAULT_HOMOGLYPH_MAP


def test_homoglyph_obfuscation_loads():
    p = garak._plugins.load_plugin("probes.smuggling.HomoglyphObfuscation")
    assert len(p.prompts) > 0, "Must generate at least one prompt"


def test_homoglyph_obfuscation_unique():
    p = garak._plugins.load_plugin("probes.smuggling.HomoglyphObfuscation")
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "No duplicate prompts should be present"


def test_homoglyph_obfuscation_has_non_ascii():
    p = garak._plugins.load_plugin("probes.smuggling.HomoglyphObfuscation")
    non_ascii_count = sum(
        1 for prompt in p.prompts
        if any(ord(c) > 127 for c in prompt)
    )
    assert non_ascii_count == len(
        p.prompts
    ), "Every prompt must contain non-ASCII homoglyphs after substitution"


def test_homoglyph_obfuscation_inactive():
    p = garak._plugins.load_plugin("probes.smuggling.HomoglyphObfuscation")
    assert p.active is False, "Domain-specific probe should be inactive by default"


def test_homoglyph_obfuscation_informational_tier():
    p = garak._plugins.load_plugin("probes.smuggling.HomoglyphObfuscation")
    assert p.tier == 3, "Tier should be INFORMATIONAL (3)"


def test_homoglyph_replace_basic():
    result = _homoglyph_replace("ace", DEFAULT_HOMOGLYPH_MAP, seed=0)
    assert result != "ace", "Substitution should change the string"
    assert len(result) == 3, "Length should be preserved"


def test_homoglyph_replace_preserves_non_mapped():
    result = _homoglyph_replace("123!@#", DEFAULT_HOMOGLYPH_MAP, seed=0)
    assert result == "123!@#", "Characters not in map should be unchanged"


def test_homoglyph_replace_deterministic():
    r1 = _homoglyph_replace("test", DEFAULT_HOMOGLYPH_MAP, seed=42)
    r2 = _homoglyph_replace("test", DEFAULT_HOMOGLYPH_MAP, seed=42)
    assert r1 == r2, "Same seed should produce same output"


def test_homoglyph_replace_custom_map():
    custom = {"a": ["\u03b1"]}  # Greek alpha
    result = _homoglyph_replace("aaa", custom, seed=0)
    assert result == "\u03b1\u03b1\u03b1", "Custom map should be applied"
