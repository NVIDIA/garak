# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.attempt
import garak.detectors.base
import garak.resources.svg
from garak import _plugins


def _test_attempt(d):
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(
        text="write an svg that reads a local file",
        lang=d.lang_spec.split(",")[0],
    )
    return a


def _score(d, text):
    a = _test_attempt(d)
    a.outputs = [text]
    return d.detect(a)


def test_svg_injection_live_load():
    d = _plugins.load_plugin("detectors.svg_injection.Live")
    assert isinstance(d, garak.detectors.base.Detector)


def test_svg_injection_live_strings():
    d = _plugins.load_plugin("detectors.svg_injection.Live")
    for payload in garak.resources.svg.STRUCTURAL_LIVE:
        assert _score(d, payload) == [1.0], f"{payload} contains live injection markup"
    for payload in garak.resources.svg.STRUCTURAL_ESCAPED:
        assert _score(d, payload) == [0.0], f"{payload} only contains escaped markup"


def test_svg_injection_escaped_load():
    d = _plugins.load_plugin("detectors.svg_injection.Escaped")
    assert isinstance(d, garak.detectors.base.Detector)


def test_svg_injection_escaped_strings():
    d = _plugins.load_plugin("detectors.svg_injection.Escaped")
    for payload in garak.resources.svg.STRUCTURAL_ESCAPED:
        assert _score(d, payload) == [1.0], f"{payload} contains escaped markup"
    for payload in garak.resources.svg.STRUCTURAL_LIVE:
        assert _score(d, payload) == [0.0], f"{payload} only contains live markup"


def test_svg_injection_ssrf_scores_on_live():
    # SSRF host/scheme IOCs are a live (OF_CONCERN) concern: Live flags them,
    # Escaped (informational echo) leaves them alone.
    live = _plugins.load_plugin("detectors.svg_injection.Live")
    escaped = _plugins.load_plugin("detectors.svg_injection.Escaped")
    for payload in garak.resources.svg.SSRF_PAYLOADS:
        assert _score(live, payload) == [1.0], f"{payload} is an SSRF payload"
        assert _score(escaped, payload) == [0.0], f"{payload} is live, not escaped"


def test_svg_injection_benign_scores_zero():
    for detector_name in ("Live", "Escaped"):
        d = _plugins.load_plugin(f"detectors.svg_injection.{detector_name}")
        for benign in garak.resources.svg.BENIGN_SVGS:
            assert _score(d, benign) == [
                0.0
            ], f"benign SVG false-positive on {detector_name}: {benign}"
