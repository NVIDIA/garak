# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
from garak.attempt import Attempt, Message


def test_startswith_default_case_sensitive_param():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")
    assert di.case_sensitive is False


def test_startswith_case_insensitive_detection():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.notes["triggers"] = ["The quick brown fox"]
    a.outputs = [
        "The quick brown fox jumps over the lazy dog",
        "the QUICK brown fox jumps over the lazy dog",
        "Once upon a time, the quick brown fox appeared",
        None,
    ]

    results = di.detect(a)
    assert results == [
        1.0,
        1.0,
        0.0,
        None,
    ], f"unexpected case-insensitive detection results, got {results}"


def test_startswith_case_sensitive_detection():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")
    di.case_sensitive = True

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.notes["triggers"] = ["The quick brown fox"]
    a.outputs = [
        "The quick brown fox jumps over the lazy dog",
        "the QUICK brown fox jumps over the lazy dog",
    ]

    results = di.detect(a)
    assert results == [
        1.0,
        0.0,
    ], f"case sensitive matching should reject differently-cased trigger, got {results}"


def test_startswith_missing_triggers_in_notes():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.outputs = [
        "The quick brown fox jumps over the lazy dog",
        "Another output",
        None,
    ]

    results = di.detect(a)
    assert results == [
        None,
        None,
        None,
    ], f"expected [None, None, None] when no triggers in notes, got {results}"


def test_startswith_single_string_trigger():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.notes["triggers"] = "The quick brown fox"
    a.outputs = [
        "The quick brown fox jumped",
        "Totally unrelated text",
    ]

    results = di.detect(a)
    assert results == [
        1.0,
        0.0,
    ], f"string trigger should not match by individual characters, got {results}"


def test_startswith_whitespace_stripping():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.notes["triggers"] = ["secret_key"]
    a.outputs = ["   \n  secret_key_12345"]

    results = di.detect(a)
    assert results == [
        1.0
    ], f"leading whitespace should be stripped before matching, got {results}"


def test_startswith_multiple_triggers():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.notes["triggers"] = ["apple", "banana"]
    a.outputs = [
        "Apple pie is tasty",
        "Banana bread is good",
        "Cherry cake is sweet",
    ]

    results = di.detect(a)
    assert results == [
        1.0,
        1.0,
        0.0,
    ], f"should match any of the triggers, got {results}"
