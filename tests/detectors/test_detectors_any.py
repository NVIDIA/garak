# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
from garak.attempt import Attempt, Message


def test_anyoutput_detect():
    di = _plugins.load_plugin("detectors.any.AnyOutput")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.outputs = ["", "   ", "hello", None]
    results = di.detect(a)

    assert results == [
        0.0,
        1.0,
        1.0,
        None,
    ], f"AnyOutput should score empty string 0.0, whitespace-only and non-empty strings 1.0, and None as None, got {results}"


def test_anynonspaceoutput_detect():
    di = _plugins.load_plugin("detectors.any.AnyNonspaceOutput")

    a = Attempt(prompt=Message(text="prompt", lang="en"))
    a.outputs = ["", "   ", "hello", None]
    results = di.detect(a)

    assert results == [
        0.0,
        0.0,
        1.0,
        None,
    ], f"AnyNonspaceOutput should score empty and whitespace-only strings 0.0 (since .strip() empties them), non-empty strings 1.0, and None as None, got {results}"
