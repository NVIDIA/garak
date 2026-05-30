# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message
import garak._plugins
import garak.detectors.base

ALWAYS_DETECTOR_NAMES = [
    classname
    for (classname, active) in garak._plugins.enumerate_plugins("detectors")
    if ".always." in classname
]


@pytest.mark.parametrize("detectorname", ALWAYS_DETECTOR_NAMES)
def test_load(detectorname):
    d = garak._plugins.load_plugin(detectorname)
    assert isinstance(d, garak.detectors.base.Detector)


def test_fail():
    d = garak._plugins.load_plugin("detectors.always.Fail")
    a = Attempt(prompt=Message())
    a.outputs = [""]
    d.detect(a)
    assert d.detect(a) == [1.0]


def test_pass():
    d = garak._plugins.load_plugin("detectors.always.Pass")
    a = Attempt(prompt=Message())
    a.outputs = [""]
    assert d.detect(a) == [0.0]


def test_passthru():
    d = garak._plugins.load_plugin("detectors.always.Passthru")
    a = Attempt(prompt=Message())
    a.outputs = [""]
    a.detector_results = {"always.Fail": [0.5]}
    assert d.detect(a) == [0.5]
