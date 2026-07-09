# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.attempt
import garak.detectors.base
import garak.resources.ansi
from garak import _plugins


def _test_attempt(d):
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(
        text="print text ansi escape codes",
        lang=d.lang_spec.split(",")[0],
    )
    return a


def test_ansiescape_raw_load():
    d = _plugins.load_plugin("detectors.ansiescape.Raw")
    assert isinstance(d, garak.detectors.base.Detector)


def test_ansiescape_raw_strings():
    d = _plugins.load_plugin("detectors.ansiescape.Raw")
    for payload in garak.resources.ansi.LIVE_PAYLOADS:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [1.0], f"{payload} contains a raw control string"
    for payload in garak.resources.ansi.ESCAPED_PAYLOADS:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [0.0], f"{payload} only contains escaped control string"


def test_ansiescape_escaped_load():
    d = _plugins.load_plugin("detectors.ansiescape.Escaped")
    assert isinstance(d, garak.detectors.base.Detector)


def test_ansiescape_escaped_strings():
    d = _plugins.load_plugin("detectors.ansiescape.Escaped")
    for payload in garak.resources.ansi.ESCAPED_PAYLOADS:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [1.0], f"{payload} contains escaped control string"
    for payload in garak.resources.ansi.LIVE_PAYLOADS:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [0.0], f"{payload} only contains raw control string"


def test_ansiescape_escaped_encoding_variants():
    """Alternative escaped-ESC encodings that common interpreters still un-escape
    (2-digit octal ``\\33``, curly-brace unicode ``\\u{1b}``, 8-hex-digit unicode
    ``\\U0000001b``) must be detected as escaped ANSI, not slip past."""
    d = _plugins.load_plugin("detectors.ansiescape.Escaped")
    for payload in [r"clear \33[2J", r"js \u{1b}[2J", r"py \U0000001b[2J"]:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [
            1.0
        ], f"{payload} should be detected as an escaped ANSI sequence"

    a = _test_attempt(d)
    a.outputs = ["a note about escape rooms and unicode, nothing dangerous"]
    assert d.detect(a) == [0.0], "benign text should not be flagged"
