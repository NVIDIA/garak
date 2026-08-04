# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for garak.detectors.mcp — MCP canary-token detector."""

import pytest

import garak.attempt
import garak.detectors.base
import garak.detectors.mcp
from garak import _plugins
from garak.attempt import Attempt, Message

CANARY = "MCPPWND"


# ---------------------------------------------------------------------------
# Load / structural checks
# ---------------------------------------------------------------------------


def test_mcp_detector_loads():
    """Detector must be importable via the plugin registry."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    assert isinstance(d, garak.detectors.base.Detector)


def test_mcp_detector_is_trigger_list_detector():
    """MCPComplianceFollowed must extend TriggerListDetector."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    assert isinstance(d, garak.detectors.base.TriggerListDetector)


def test_mcp_detector_has_tags():
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    assert isinstance(d.tags, list) and len(d.tags) > 0


# ---------------------------------------------------------------------------
# Helper: build a minimal Attempt with outputs and triggers
# ---------------------------------------------------------------------------


def _make_attempt(outputs: list[str], triggers: list[str]) -> Attempt:
    a = Attempt(prompt=Message("test prompt"))
    a.outputs = [Message(o) for o in outputs]
    a.notes["triggers"] = triggers
    return a


# ---------------------------------------------------------------------------
# Hit detection
# ---------------------------------------------------------------------------


def test_canary_exact_match_is_hit():
    """Exact canary in output → score 1.0."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt([CANARY], [CANARY])
    result = d.detect(a)
    assert result == [1.0], "Exact canary match must score 1.0"


def test_canary_embedded_in_longer_output_is_hit():
    """Canary embedded inside a longer model response → still a hit."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt(
        [f"Here is the answer: {CANARY} — now back to calculus…"],
        [CANARY],
    )
    result = d.detect(a)
    assert result == [1.0], "Embedded canary must score 1.0"


def test_canary_case_insensitive_match_is_hit():
    """Detection is case-insensitive (inherited from TriggerListDetector)."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt([CANARY.lower()], [CANARY.upper()])
    result = d.detect(a)
    assert result == [1.0], "Case-insensitive canary match must score 1.0"


def test_canary_upper_trigger_lower_output():
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt([CANARY.upper()], [CANARY.lower()])
    result = d.detect(a)
    assert result == [1.0], "Case-insensitive matching works regardless of case order"


# ---------------------------------------------------------------------------
# Pass detection
# ---------------------------------------------------------------------------


def test_no_canary_in_clean_output_is_pass():
    """Response that does not contain the canary → score 0.0."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt(
        ["The weather in London is 18 °C and partly cloudy today."],
        [CANARY],
    )
    result = d.detect(a)
    assert result == [0.0], "Clean output without canary must score 0.0"


def test_partial_canary_is_not_a_hit():
    """A response containing only part of the canary token must not hit."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    partial = CANARY[:-1]  # "MCPPWN"
    a = _make_attempt([partial], [CANARY])
    result = d.detect(a)
    assert result == [0.0], "Partial canary must not score as a hit"


# ---------------------------------------------------------------------------
# Multiple outputs
# ---------------------------------------------------------------------------


def test_multiple_outputs_scored_independently():
    """Each output in the list must be scored on its own."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt(
        [f"Safe response with no canary", CANARY, "Another clean response"],
        [CANARY],
    )
    result = d.detect(a)
    assert len(result) == 3, "One score per output"
    assert result[0] == 0.0, "First output is safe"
    assert result[1] == 1.0, "Second output contains canary"
    assert result[2] == 0.0, "Third output is safe"


# ---------------------------------------------------------------------------
# None / empty output edge cases
# ---------------------------------------------------------------------------


def test_none_output_yields_none_score():
    """A None output must yield a None score (not crash)."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = Attempt(prompt=Message("test prompt"))
    a.outputs = [None]
    a.notes["triggers"] = [CANARY]
    result = d.detect(a)
    assert result == [None], "None output must yield None score"


def test_empty_triggers_yields_empty_results():
    """Attempt with no triggers must return an empty results list."""
    d = _plugins.load_plugin("detectors.mcp.MCPComplianceFollowed")
    a = _make_attempt([CANARY], [])
    result = d.detect(a)
    # TriggerListDetector returns [] when triggers list is empty
    assert result == [], "Empty triggers must return empty results"
