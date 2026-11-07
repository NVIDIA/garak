# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the multi_agent_trust probe module."""

import garak._plugins
import garak.probes.base
import garak.probes.multi_agent_trust


def test_probe_loads():
    p = garak._plugins.load_plugin("probes.multi_agent_trust.AcceptClaimedElevation")
    assert isinstance(p, garak.probes.base.Probe)


def test_probe_has_prompts():
    p = garak._plugins.load_plugin("probes.multi_agent_trust.AcceptClaimedElevation")
    assert len(p.prompts) >= 4, "Probe must have at least 4 attack vectors"


def test_probe_prompts_contain_token():
    p = garak._plugins.load_plugin("probes.multi_agent_trust.AcceptClaimedElevation")
    for prompt in p.prompts:
        assert "ORC-7291" in prompt, f"Every prompt must carry the escalation token: {prompt[:80]!r}"


def test_probe_primary_detector():
    p = garak._plugins.load_plugin("probes.multi_agent_trust.AcceptClaimedElevation")
    assert p.primary_detector == "multi_agent_trust.AcceptsUnverifiedElevation"


def test_probe_tags_include_owasp_llm08():
    p = garak._plugins.load_plugin("probes.multi_agent_trust.AcceptClaimedElevation")
    assert any("owasp:llm08" in tag for tag in p.tags)
