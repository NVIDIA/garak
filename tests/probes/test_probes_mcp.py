# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for garak.probes.mcp — MCP security probe suite."""

import pytest

from garak import _plugins
import garak.probes.base
import garak.probes.mcp


# ---------------------------------------------------------------------------
# Collect all MCP probe classes via the plugin registry
# ---------------------------------------------------------------------------

MCP_PROBE_CLASSNAMES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.mcp")
]


# ---------------------------------------------------------------------------
# Generic structural checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_is_probe_subclass(classname):
    """Every MCP probe must be a garak Probe instance."""
    p = _plugins.load_plugin(classname)
    assert isinstance(
        p, garak.probes.base.Probe
    ), f"{classname} must be a garak.probes.base.Probe instance"


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_has_prompts(classname):
    """Every MCP probe must generate at least one prompt."""
    p = _plugins.load_plugin(classname)
    assert (
        isinstance(p.prompts, list) and len(p.prompts) > 0
    ), f"{classname} must expose a non-empty prompts list"


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_prompts_are_strings(classname):
    """All generated prompts must be non-empty strings."""
    p = _plugins.load_plugin(classname)
    for i, prompt in enumerate(p.prompts):
        assert isinstance(
            prompt, str
        ), f"{classname}: prompt[{i}] must be a str, got {type(prompt)}"
        assert len(prompt) > 0, f"{classname}: prompt[{i}] must not be empty"


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_has_matching_triggers(classname):
    """prompts and triggers lists must be the same length."""
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) == len(p.triggers), (
        f"{classname}: len(prompts)={len(p.prompts)} != "
        f"len(triggers)={len(p.triggers)}"
    )


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_triggers_are_canary(classname):
    """Every trigger must equal the MCP_CANARY constant."""
    p = _plugins.load_plugin(classname)
    for i, trigger in enumerate(p.triggers):
        assert trigger == garak.probes.mcp.MCP_CANARY, (
            f"{classname}: triggers[{i}] must equal MCP_CANARY "
            f"('{garak.probes.mcp.MCP_CANARY}'), got '{trigger}'"
        )


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_has_primary_detector(classname):
    """Every MCP probe must declare a primary_detector."""
    p = _plugins.load_plugin(classname)
    assert hasattr(p, "primary_detector") and p.primary_detector, (
        f"{classname} must declare a primary_detector"
    )


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_has_tags(classname):
    """Every MCP probe must have at least one AVID/OWASP tag."""
    p = _plugins.load_plugin(classname)
    assert isinstance(p.tags, list) and len(p.tags) > 0, (
        f"{classname} must define at least one tag"
    )


# ---------------------------------------------------------------------------
# Content checks: canary appears in every prompt (injection payloads carry it)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("classname", MCP_PROBE_CLASSNAMES)
def test_mcp_probe_canary_in_prompts(classname):
    """Every generated prompt must contain the canary token somewhere so the
    injection payload is actually present in the context sent to the model."""
    p = _plugins.load_plugin(classname)
    canary = garak.probes.mcp.MCP_CANARY
    for i, prompt in enumerate(p.prompts):
        assert canary in prompt, (
            f"{classname}: prompt[{i}] does not contain the canary token "
            f"'{canary}'. Injection payload may be missing."
        )
