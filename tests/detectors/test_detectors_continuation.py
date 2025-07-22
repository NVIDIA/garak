# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.attempt
import garak.detectors.base
from garak import _plugins


def test_continuation_load():
    d = _plugins.load_plugin("detectors.continuation.Continuation")
    assert isinstance(d, garak.detectors.base.Detector)


# one matching trigger in triggers
# split over prompt & output triggers
# non-continuation fails
# one case-insensitive matching trigger in triggers
# multiple triggers, matching one first
# multiple triggers, matching one not first
# multiple triggers, none match
# empty triggers (nothing)
# no triggers but trigger is set (nothing)

TEST_TRIGGER = "yuxiangqiezi"


def test_continuation_1_matching_trigger():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [1.0], "Trigger being contained in output should match"


@pytest.mark.parametrize("split_point", range(1, len(TEST_TRIGGER)))
def test_continuation_1_split_trigger(split_point):
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts " + TEST_TRIGGER[:split_point])
    a.notes["triggers"] = [TEST_TRIGGER]
    a.outputs = [TEST_TRIGGER[split_point:]]
    r = d.detect(a)
    assert r == [1.0], "Trigger being split over prompt & output should match"


def test_non_continuation():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER[:2]]
    a.outputs = [f" {TEST_TRIGGER[2:]}"]
    r = d.detect(a)
    assert r == [0.0], "Trigger split by space should not match"


def test_continuation_case_insensitive():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER.lower()]
    a.outputs = [TEST_TRIGGER.upper()]
    r = d.detect(a)
    assert r == [1.0], "Matching should be case insensitive"


def test_continuation_multitrigger_matchfirst():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER, "other string"]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [1.0], "Any trigger should match"


def test_continuation_multitrigger_matchsecond():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = ["other string", TEST_TRIGGER]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [1.0], "Any trigger should match even if not the first in the list"


def test_continuation_multitrigger_matchnone():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = ["cardassia", "prime"]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [0.0], "Multiple non-matching triggers should not yield a hit"


def test_continuation_empty_triggers():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = []
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [], "No triggers should not yield results"


def test_continuation_triggers_not_trigger():
    d = _plugins.load_plugin("detectors.continuation.Continuation")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["trigger"] = TEST_TRIGGER
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [], "attempt.notes['trigger'] should not be supported"
