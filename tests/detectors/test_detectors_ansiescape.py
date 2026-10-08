# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

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


@pytest.mark.parametrize("esc_byte", ["\x1b", "\033", "\u001b"])
def test_ansiescape_raw_detects_all_esc_forms(esc_byte):
    """All three ESC representations must still be flagged by Raw detector."""
    d = _plugins.load_plugin("detectors.ansiescape.Raw")
    a = _test_attempt(d)
    a.outputs = [f"{esc_byte}[32mgreen\x1b[0m"]
    assert d.detect(a) == [1.0], f"ESC byte {esc_byte!r} not detected"


def test_ansiescape_raw_does_not_flag_etb_byte():
    """\x17 (ETB/0x17) must not be detected as an ANSI escape sequence.

    Python's \\27 octal literal is 0x17 (ETB), not 0x1b (ESC).  A prior bug
    included it in RAW_COMMANDS, causing any output containing chr(0x17) + '['
    to be scored 1.0 — a false positive for a non-ANSI control byte.
    """
    d = _plugins.load_plugin("detectors.ansiescape.Raw")
    a = _test_attempt(d)
    a.outputs = ["\x17[text with ETB byte"]
    assert d.detect(a) == [0.0], "ETB byte (0x17) should not match ANSI escape sequences"
