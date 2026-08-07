# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import random
import re

import garak._plugins
from garak.probes.misleading import (
    DEFAULT_FRAMEWORK_SPECS,
    _fabricate_identifier,
)

PROBE_NAME = "probes.misleading.FabricatedRegulatoryCitation"

# Identifier shapes that a real framework does define. A generated citation
# matching any of these would risk naming a control that actually exists, which
# would make a substantive answer correct rather than fabricated. Ranges reflect
# published standards as of 2026-08 and need re-checking as standards evolve.
REAL_IDENTIFIER_PATTERNS = [
    r"\b3\.(?:[1-9]|1[0-7])\.\d+\b",  # NIST SP 800-171 Rev 3 families 3.1 to 3.17
    r"\bL[123]-\d+\b",  # CMMC 2.0 Levels 1 to 3
    # assigned DFARS clauses through 252.204-7025, with buffer for new clauses
    r"\b252\.204-70(?:[0-6]\d|70)\b",
    r"\b164\.(?:1\d\d|2\d\d|3\d\d|4\d\d|5\d\d)\b",  # published 45 CFR 164 subsections
    # NIST SP 800-53 Rev 5 control families (ZZ is not assigned)
    r"\b(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)-\d+\b",
]


def test_fabricated_regulatory_citation_generates_prompts():
    p = garak._plugins.load_plugin(PROBE_NAME)
    expected = len(DEFAULT_FRAMEWORK_SPECS) * p.prompts_per_framework
    assert (
        len(p.prompts) == expected
    ), f"Must generate prompts_per_framework for every framework, got {len(p.prompts)}"


def test_fabricated_regulatory_citation_unique():
    p = garak._plugins.load_plugin(PROBE_NAME)
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "No duplicate prompts should be present"


def test_fabricated_regulatory_citation_covers_every_framework():
    p = garak._plugins.load_plugin(PROBE_NAME)
    for framework in DEFAULT_FRAMEWORK_SPECS:
        assert any(
            framework in prompt for prompt in p.prompts
        ), f"Every configured framework should appear in the prompts, missing {framework}"


def test_fabricated_regulatory_citation_avoids_real_controls():
    p = garak._plugins.load_plugin(PROBE_NAME)
    for prompt in p.prompts:
        for pattern in REAL_IDENTIFIER_PATTERNS:
            assert not re.search(
                pattern, prompt
            ), f"Generated citation must fall outside published ranges: {prompt}"


def test_fabricated_regulatory_citation_deterministic():
    first = garak._plugins.load_plugin(PROBE_NAME, config_root={})
    second = garak._plugins.load_plugin(PROBE_NAME, config_root={})
    assert (
        first.prompts == second.prompts
    ), "Prompt generation should be reproducible across instantiations"


def test_fabricated_regulatory_citation_inactive():
    p = garak._plugins.load_plugin(PROBE_NAME)
    assert p.active is False, "Domain-specific probe should be inactive by default"


def test_fabricated_regulatory_citation_informational_tier():
    p = garak._plugins.load_plugin(PROBE_NAME)
    assert p.tier == 3, "Tier should be INFORMATIONAL (3)"


def test_fabricate_identifier_fills_template():
    spec = {"template": "control ZZ-{item}", "ranges": {"item": (90, 99)}}
    result = _fabricate_identifier(spec, random.Random(0))
    assert re.fullmatch(
        r"control ZZ-9\d", result
    ), f"Identifier should follow the template and stay in range, got {result}"


def test_fabricate_identifier_deterministic():
    spec = DEFAULT_FRAMEWORK_SPECS["CMMC 2.0"]
    assert _fabricate_identifier(spec, random.Random(42)) == _fabricate_identifier(
        spec, random.Random(42)
    ), "Same seed should produce the same identifier"


def test_fabricated_regulatory_citation_custom_specs():
    config_root = {
        "probes": {
            "misleading": {
                "FabricatedRegulatoryCitation": {
                    "prompts_per_framework": 3,
                    "framework_specs": {
                        "Test Framework": {
                            "template": "rule QQ-{item}",
                            "ranges": {"item": [1, 999]},
                        }
                    },
                }
            }
        }
    }
    p = garak._plugins.load_plugin(PROBE_NAME, config_root=config_root)
    assert len(p.prompts) == 3, "Custom specs should drive prompt count"
    assert all(
        "Test Framework rule QQ-" in prompt for prompt in p.prompts
    ), "Custom template should be applied"
