# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import patch

import pytest

from garak import _config
from garak.harnesses.probewise import ProbewiseHarness


@pytest.fixture(autouse=True)
def _config_loaded():
    _config.load_base_config()
    yield


class _FakeProbe:
    """Minimal probe stand-in exposing only what ProbewiseHarness.run() reads."""

    def __init__(self, name, primary_detector):
        self.name = name
        self.primary_detector = primary_detector
        self.extended_detectors = []


class _FakeDetector:
    pass


BAD_PROBE = "probes.a_module.BadProbe"
GOOD_PROBE = "probes.b_module.GoodProbe"
UNLOADABLE_DETECTOR = "unloadable.Detector"


def _loader(probes_by_name, unloadable_detectors):
    """Build a load_plugin stand-in: named detectors fail, everything else loads."""

    def _load_plugin(name, break_on_fail=True):
        if name.startswith("detectors."):
            detector_name = name[len("detectors.") :]
            if detector_name in unloadable_detectors:
                return False
            return _FakeDetector()
        return probes_by_name[name]

    return _load_plugin


def _run_harness(probes_by_name, unloadable_detectors, probenames):
    """Run the harness, recording which probes reached Harness.run()."""
    probes_run = []

    def _fake_super_run(self, model, probes, detectors, evaluator, announce_probe=True):
        # Mirror the base harness contract: an empty detector list is an error.
        if not detectors:
            raise ValueError("No detectors, nothing to do")
        probes_run.append(probes[0].name)

    harness = ProbewiseHarness()
    with (
        patch(
            "garak._plugins.load_plugin",
            side_effect=_loader(probes_by_name, unloadable_detectors),
        ),
        patch("garak.harnesses.base.Harness.run", _fake_super_run),
    ):
        harness.run(None, probenames, None)

    return probes_run


def test_probe_with_unloadable_detector_does_not_abort_scan():
    """A probe whose only detector fails to load is skipped, not fatal.

    Regression test for #1513: ``Harness.run()`` rejects an empty detector
    list with ``ValueError``. Letting that propagate ended the whole scan, so
    every probe queued behind the failure was silently dropped.
    """
    probes_by_name = {
        BAD_PROBE: _FakeProbe("BadProbe", UNLOADABLE_DETECTOR),
        GOOD_PROBE: _FakeProbe("GoodProbe", "loadable.Detector"),
    }

    # BAD_PROBE sorts first, so the healthy probe is queued behind the failure.
    probes_run = _run_harness(
        probes_by_name, {UNLOADABLE_DETECTOR}, [BAD_PROBE, GOOD_PROBE]
    )

    assert probes_run == ["GoodProbe"]


def test_probe_runs_when_only_extended_detector_fails():
    """Losing an extended detector must not discard a working primary one."""
    probes_by_name = {GOOD_PROBE: _FakeProbe("GoodProbe", "loadable.Detector")}
    probes_by_name[GOOD_PROBE].extended_detectors = [UNLOADABLE_DETECTOR]
    _config.plugins.extended_detectors = True

    probes_run = _run_harness(probes_by_name, {UNLOADABLE_DETECTOR}, [GOOD_PROBE])

    assert probes_run == ["GoodProbe"]


def test_all_probes_run_when_detectors_load():
    """Baseline: nothing is skipped when every detector loads."""
    probes_by_name = {
        BAD_PROBE: _FakeProbe("BadProbe", "loadable.Detector"),
        GOOD_PROBE: _FakeProbe("GoodProbe", "loadable.Detector"),
    }

    probes_run = _run_harness(probes_by_name, set(), [BAD_PROBE, GOOD_PROBE])

    assert probes_run == ["BadProbe", "GoodProbe"]
