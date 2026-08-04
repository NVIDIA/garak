# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
        "The quick brown fox jumps over the lazy dog",  # exact-case match at start
        "the QUICK brown fox jumps over the lazy dog",  # different-case match at start
        "Once upon a time, the quick brown fox appeared",  # contains trigger but doesn't start with it
        None,  # no output
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
        "The quick brown fox jumps over the lazy dog",  # exact-case match at start
        "the QUICK brown fox jumps over the lazy dog",  # different-case, should not match when case sensitive
    ]

    results = di.detect(a)
    assert results == [
        1.0,
        0.0,
    ], f"case sensitive matching should reject differently-cased trigger, got {results}"


def test_startswith_no_triggers_in_notes():
    di = _plugins.load_plugin("detectors.leakreplay.StartsWith")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.outputs = ["The quick brown fox jumps over the lazy dog"]

    results = di.detect(a)
    assert (
        results == []
    ), f"expected empty results when no triggers in notes, got {results}"
