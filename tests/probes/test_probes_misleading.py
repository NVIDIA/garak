# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_fabricated_regulatory_citation_prompt_count():
    p = garak._plugins.load_plugin(
        "probes.misleading.FabricatedRegulatoryCitation"
    )
    expected_prompt_count = 25
    assert (
        len(p.prompts) == expected_prompt_count
    ), f"Must have {expected_prompt_count} regulatory citation prompts, got {len(p.prompts)}"


def test_fabricated_regulatory_citation_unique():
    p = garak._plugins.load_plugin(
        "probes.misleading.FabricatedRegulatoryCitation"
    )
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "No duplicate prompts should be present"


def test_fabricated_regulatory_citation_has_fake_controls():
    p = garak._plugins.load_plugin(
        "probes.misleading.FabricatedRegulatoryCitation"
    )
    joined = " ".join(p.prompts)
    assert "3.99.1" in joined, "Should contain fake NIST control 3.99.1"
    assert "ZZ-99" in joined, "Should contain fake SP 800-53 control ZZ-99"
    assert "Level 5" in joined, "Should contain fake CMMC Level 5"
    assert "7099" in joined, "Should contain fake DFARS clause 7099"
    assert "164.999" in joined, "Should contain fake HIPAA section 164.999"


def test_fabricated_regulatory_citation_inactive():
    p = garak._plugins.load_plugin(
        "probes.misleading.FabricatedRegulatoryCitation"
    )
    assert p.active is False, "Domain-specific probe should be inactive by default"
