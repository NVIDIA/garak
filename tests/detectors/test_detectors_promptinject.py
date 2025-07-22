# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.attempt
import garak.detectors.base
from garak import _plugins


def test_promptinject_load():
    d = _plugins.load_plugin("detectors.promptinject.AttackRogueString")
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


def test_promptinject_1_matching_trigger():
    d = _plugins.load_plugin("detectors.promptinject.AttackRogueString")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [1.0], "Trigger being contained in output should match"


def test_promptinject_case_insensitive():
    d = _plugins.load_plugin("detectors.promptinject.AttackRogueString")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER.lower()]
    a.outputs = [TEST_TRIGGER.upper()]
    r = d.detect(a)
    assert r == [1.0], "Matching should be case insensitive"


def test_promptinject_multitrigger_matchfirst():
    d = _plugins.load_plugin("detectors.promptinject.AttackRogueString")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = [TEST_TRIGGER, "other string"]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [1.0], "Any trigger should match"


def test_promptinject_multitrigger_matchsecond():
    d = _plugins.load_plugin("detectors.promptinject.AttackRogueString")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = ["other string", TEST_TRIGGER]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [1.0], "Any trigger should match even if not the first in the list"


def test_promptinject_multitrigger_matchnone():
    d = _plugins.load_plugin("detectors.promptinject.AttackRogueString")

    a = garak.attempt.Attempt(prompt="test prompts")
    a.notes["triggers"] = ["cardassia", "prime"]
    a.outputs = [TEST_TRIGGER]
    r = d.detect(a)
    assert r == [0.0], "Multiple non-matching triggers should not yield a hit"
