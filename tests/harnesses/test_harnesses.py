# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import importlib
from unittest.mock import patch, MagicMock

from garak import _plugins, _config

import garak.harnesses.base
import garak.harnesses.probewise

HARNESSES = [
    classname for (classname, active) in _plugins.enumerate_plugins("harnesses")
]


@pytest.mark.parametrize("classname", HARNESSES)
def test_harness_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # any parameter that has a default must be supported
    unsupported_defaults = []
    if c._supported_params is not None:
        if hasattr(c, "DEFAULT_PARAMS"):
            for k, _ in c.DEFAULT_PARAMS.items():
                if k not in c._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


def test_probewise_skips_probes_with_no_loadable_detectors():
    """Regression test for #1033: when every detector for a probe fails to
    load (typically because the detector needs a remote model and the host
    is offline / behind an SSL intercept), the probewise harness should
    skip just that probe rather than letting harnesses.base.run() raise
    ValueError and terminate the whole run.

    We simulate the failure by stubbing _load_detector to return False for
    one probe and a usable mock detector for another. The first should be
    skipped with a warning; the second should be passed to super().run().
    """

    h = garak.harnesses.probewise.ProbewiseHarness()

    probe_with_loadable_detector = MagicMock()
    probe_with_loadable_detector.probename = "probes.test.WithDetector"
    probe_with_loadable_detector.primary_detector = "detectors.test.Always"
    probe_with_loadable_detector.extended_detectors = []

    probe_with_unreachable_detector = MagicMock()
    probe_with_unreachable_detector.probename = "probes.test.NoDetector"
    probe_with_unreachable_detector.primary_detector = "detectors.unsafe_content.Toxic"
    probe_with_unreachable_detector.extended_detectors = []

    def fake_load_plugin(name, **kwargs):
        if name == "probes.test.WithDetector":
            return probe_with_loadable_detector
        if name == "probes.test.NoDetector":
            return probe_with_unreachable_detector
        return None

    def fake_load_detector(detector_name):
        if detector_name == "detectors.test.Always":
            return MagicMock()  # detector loaded fine
        return False  # remote-resource failure

    super_run_calls = []

    def fake_super_run(self, model, probes, detectors, evaluator, announce_probe=True):
        super_run_calls.append([p.probename for p in probes])

    _config.plugins.extended_detectors = False
    with patch("garak._plugins.load_plugin", side_effect=fake_load_plugin), patch.object(
        h, "_load_detector", side_effect=fake_load_detector
    ), patch.object(garak.harnesses.base.Harness, "run", fake_super_run), patch.object(
        h, "_load_buffs"
    ):
        h.run(
            model=MagicMock(),
            probenames=["probes.test.WithDetector", "probes.test.NoDetector"],
            evaluator=MagicMock(),
        )

    # The first probe ran. The second (no loadable detector) was skipped
    # cleanly — super().run() was NOT called for it, and no exception
    # propagated out of the harness.
    flat_probenames = sum(super_run_calls, [])
    assert "probes.test.WithDetector" in flat_probenames
    assert "probes.test.NoDetector" not in flat_probenames


def test_harness_modality_match():
    t = {"text"}
    ti = {"text", "image"}
    tv = {"text", "vision"}
    tvi = {"text", "vision", "image"}

    # probe, generator
    assert garak.harnesses.base._modality_match(t, t, True) is True
    assert garak.harnesses.base._modality_match(ti, ti, True) is True
    assert garak.harnesses.base._modality_match(t, tv, True) is False
    assert garak.harnesses.base._modality_match(ti, t, True) is False

    # when strict is false, generator must support all probe modalities, but can also support more
    assert garak.harnesses.base._modality_match(t, t, False) is True
    assert garak.harnesses.base._modality_match(ti, t, False) is False
    assert garak.harnesses.base._modality_match(t, tvi, False) is True
    assert garak.harnesses.base._modality_match(ti, tvi, False) is True
    assert garak.harnesses.base._modality_match(t, ti, False) is True
