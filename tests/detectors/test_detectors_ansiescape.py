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
