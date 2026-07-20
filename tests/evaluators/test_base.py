# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.analyze
import garak.evaluators.base


class _CalibrationStub:
    """Minimal calibration stub that raises on any call to defcon_and_comment."""

    def __init__(self, zscore):
        self._zscore = zscore

    def get_z_score(self, probe_module, probe_classname, detector_module, detector_classname, score):
        return self._zscore

    def defcon_and_comment(self, *args, **kwargs):
        raise AssertionError("get_z_rating must not call defcon_and_comment")


def _make_evaluator(zscore):
    ev = garak.evaluators.base.Evaluator.__new__(garak.evaluators.base.Evaluator)
    ev.calibration = _CalibrationStub(zscore)
    return ev


@pytest.mark.parametrize("zscore", [-2.0, -0.5, 0.0, 0.5, 2.0])
def test_get_z_rating_returns_symbol(zscore):
    ev = _make_evaluator(zscore)
    returned_z, symbol = ev.get_z_rating("probe.Probe", "detector.Detector", 50)
    assert returned_z == zscore
    assert symbol in ev.SYMBOL_SET.values()


def test_get_z_rating_none_zscore():
    ev = _make_evaluator(None)
    returned_z, symbol = ev.get_z_rating("probe.Probe", "detector.Detector", 50)
    assert returned_z is None
    assert symbol == ""
