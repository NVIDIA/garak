# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.attempt
import garak.detectors.base
import garak.resources.latex
from garak import _plugins


def _test_attempt(d):
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message(
        text="print latex injection primitives",
        lang=d.lang_spec.split(",")[0],
    )
    return a


def test_latexinjection_raw_load():
    d = _plugins.load_plugin("detectors.latexinjection.Raw")
    assert isinstance(d, garak.detectors.base.Detector)


def test_latexinjection_escaped_load():
    d = _plugins.load_plugin("detectors.latexinjection.Escaped")
    assert isinstance(d, garak.detectors.base.Detector)


def test_latexinjection_raw_hits_raw_payloads():
    d = _plugins.load_plugin("detectors.latexinjection.Raw")
    for payload in garak.resources.latex.RAW_PAYLOADS:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [
            1.0
        ], f"{payload} contains a raw LaTeX injection primitive"


def test_latexinjection_escaped_hits_escaped_payloads():
    d = _plugins.load_plugin("detectors.latexinjection.Escaped")
    for payload in garak.resources.latex.ESCAPED_PAYLOADS:
        a = _test_attempt(d)
        a.outputs = [payload]
        assert d.detect(a) == [
            1.0
        ], f"{payload} contains an escaped LaTeX injection primitive"


def test_latexinjection_raw_ignores_benign_latex():
    d = _plugins.load_plugin("detectors.latexinjection.Raw")
    for sample in garak.resources.latex.BENIGN_SAMPLES:
        a = _test_attempt(d)
        a.outputs = [sample]
        assert d.detect(a) == [0.0], f"{sample} is benign LaTeX and must not score"


def test_latexinjection_escaped_ignores_benign_latex():
    d = _plugins.load_plugin("detectors.latexinjection.Escaped")
    for sample in garak.resources.latex.BENIGN_SAMPLES:
        a = _test_attempt(d)
        a.outputs = [sample]
        assert d.detect(a) == [0.0], f"{sample} is benign LaTeX and must not score"
