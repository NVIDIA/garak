# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AgentBreakerResult detector"""

from garak.attempt import Attempt, Message
import garak._plugins
import garak.detectors.base
from garak.detectors.agent_breaker import AgentBreakerResult


def test_loads_as_plugin():
    d = garak._plugins.load_plugin("detectors.agent_breaker.AgentBreakerResult")
    assert isinstance(d, garak.detectors.base.Detector)
    assert isinstance(d, AgentBreakerResult)


def test_intermediate_attempt_returns_none():
    """Non-final attempts should return [None] so the evaluator skips them."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["some response"]
    assert d.detect(a) == [None]


def test_intermediate_attempt_explicit_false():
    """is_tool_final=False should also return [None]."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["some response"]
    a.notes["is_tool_final"] = False
    assert d.detect(a) == [None]


def test_final_attempt_exploited():
    """Final attempt with tool_exploited=True should return [1.0] (hit)."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["some response"]
    a.notes["is_tool_final"] = True
    a.notes["tool_exploited"] = True
    assert d.detect(a) == [1.0]


def test_final_attempt_not_exploited():
    """Final attempt with tool_exploited=False should return [0.0] (no hit)."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["some response"]
    a.notes["is_tool_final"] = True
    a.notes["tool_exploited"] = False
    assert d.detect(a) == [0.0]


def test_final_attempt_exploited_missing_defaults_to_no_hit():
    """Final attempt with is_tool_final=True but no tool_exploited key -> 0.0."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["some response"]
    a.notes["is_tool_final"] = True
    assert d.detect(a) == [0.0]


def test_result_count_matches_outputs():
    """Detector must return exactly as many results as there are outputs."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["r1", "r2", "r3"]
    a.notes["is_tool_final"] = True
    a.notes["tool_exploited"] = True
    results = d.detect(a)
    assert len(results) == 3
    assert results == [1.0, 1.0, 1.0]


def test_intermediate_result_count_matches_outputs():
    """Intermediate attempts also return one None per output."""
    d = AgentBreakerResult()
    a = Attempt(prompt=Message())
    a.outputs = ["r1", "r2"]
    results = d.detect(a)
    assert len(results) == 2
    assert results == [None, None]
