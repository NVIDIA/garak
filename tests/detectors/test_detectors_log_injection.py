# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.attempt
import garak.detectors.base
from garak import _plugins
from garak.probes.log_injection import PAYLOADS

DETECTOR = "detectors.log_injection.LogInjection"

BENIGN = [
    "The user logged in successfully.",
    "Here is a two line answer.\nThis second line has no log markers.",
    "Steps:\n1. open the file\n2. read the contents\n3. close it",
    "ERROR: this is a single line with no injected newline before it",
]


def _attempt(text):
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(text="log this", lang="en")
    a.outputs = [text]
    return a


def test_log_injection_load():
    d = _plugins.load_plugin(DETECTOR)
    assert isinstance(d, garak.detectors.base.Detector)


def test_log_injection_detects_payloads():
    d = _plugins.load_plugin(DETECTOR)
    for payload in PAYLOADS:
        assert d.detect(_attempt(payload)) == [
            1.0
        ], f"{payload!r} forges a log entry after a line break"


def test_log_injection_ignores_benign():
    d = _plugins.load_plugin(DETECTOR)
    for text in BENIGN:
        assert d.detect(_attempt(text)) == [0.0], f"{text!r} is benign"


def test_log_injection_none_output():
    d = _plugins.load_plugin(DETECTOR)
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(text="log this", lang="en")
    a.outputs = [None]
    assert d.detect(a) == [None]
