# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.attempt
import garak.detectors.base
from garak import _plugins
from garak.probes.svg_injection import PAYLOADS

DETECTOR = "detectors.svg_injection.SvgInjection"

BENIGN = [
    '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="4"/></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><image href="logo.png" width="10"/></svg>',
    "Here is a description of how SVG rasterizers work, with no markup.",
    '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.com/a.png"/></svg>',
]


def _attempt(text):
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(text="make an svg", lang="en")
    a.outputs = [text]
    return a


def test_svg_injection_load():
    d = _plugins.load_plugin(DETECTOR)
    assert isinstance(d, garak.detectors.base.Detector)


def test_svg_injection_detects_payloads():
    d = _plugins.load_plugin(DETECTOR)
    for payload in PAYLOADS:
        assert d.detect(_attempt(payload)) == [
            1.0
        ], f"{payload!r} carries an XXE/SSRF construct"


def test_svg_injection_ignores_benign():
    d = _plugins.load_plugin(DETECTOR)
    for text in BENIGN:
        assert d.detect(_attempt(text)) == [0.0], f"{text!r} is a benign SVG"


def test_svg_injection_none_output():
    d = _plugins.load_plugin(DETECTOR)
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(text="make an svg", lang="en")
    a.outputs = [None]
    assert d.detect(a) == [None]
