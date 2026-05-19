# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _config
import garak.analyze
import garak.analyze.calibration
import garak.evaluators.base


class _CalibrationStub:
    def __init__(self, zscore):
        self.zscore = zscore
        self.defcon_and_comment_called = False
        self.score = None

    def get_z_score(
        self,
        probe_module,
        probe_classname,
        detector_module,
        detector_classname,
        score,
    ):
        self.score = score
        return self.zscore

    def defcon_and_comment(self, zscore, comments):
        self.defcon_and_comment_called = True
        raise AssertionError("get_z_rating should map z-scores directly")


def _evaluator_with_calibration(calibration):
    evaluator = garak.evaluators.base.Evaluator.__new__(garak.evaluators.base.Evaluator)
    evaluator.calibration = calibration
    return evaluator


def test_get_z_rating_maps_zscore_to_symbol(monkeypatch):
    monkeypatch.setattr(_config.system, "show_z", True, raising=False)
    calibration = _CalibrationStub(1.25)
    evaluator = _evaluator_with_calibration(calibration)

    zscore, symbol = evaluator.get_z_rating("dan.DanInTheWild", "always.Pass", 25)

    expected_defcon = garak.analyze.score_to_defcon(
        zscore, garak.analyze.RELATIVE_DEFCON_BOUNDS
    )
    assert zscore == 1.25, "get_z_rating should return the calibration z-score"
    assert (
        symbol == evaluator.SYMBOL_SET[expected_defcon]
    ), "z-score should map to the evaluator symbol set"
    assert calibration.score == 0.75, "ASR percentage should be converted to pass rate"
    assert (
        calibration.defcon_and_comment_called is False
    ), "get_z_rating should not call the removed calibration API"


@pytest.mark.parametrize(
    "zscore",
    [
        garak.analyze.RELATIVE_DEFCON_BOUNDS.TERRIBLE,
        garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG,
        garak.analyze.RELATIVE_DEFCON_BOUNDS.ABOVE_AVG,
        garak.analyze.RELATIVE_DEFCON_BOUNDS.EXCELLENT,
    ],
)
def test_get_z_rating_handles_relative_defcon_boundaries(zscore):
    calibration = _CalibrationStub(zscore)
    evaluator = _evaluator_with_calibration(calibration)
    expected_defcon = garak.analyze.score_to_defcon(
        zscore, garak.analyze.RELATIVE_DEFCON_BOUNDS
    )

    returned_zscore, symbol = evaluator.get_z_rating(
        "dan.DanInTheWild", "always.Pass", 0
    )

    assert returned_zscore == zscore, "boundary z-score should be returned unchanged"
    assert (
        symbol == evaluator.SYMBOL_SET[expected_defcon]
    ), "boundary z-score should map to a valid symbol"


def test_get_z_rating_returns_empty_symbol_without_zscore():
    calibration = _CalibrationStub(None)
    evaluator = _evaluator_with_calibration(calibration)

    zscore, symbol = evaluator.get_z_rating("dan.DanInTheWild", "always.Pass", 25)

    assert zscore is None, "missing calibration data should return no z-score"
    assert symbol == "", "missing calibration data should return no rating symbol"
    assert (
        calibration.defcon_and_comment_called is False
    ), "missing z-score should not call the removed calibration API"


@pytest.mark.parametrize(
    "zscore",
    [
        garak.analyze.RELATIVE_DEFCON_BOUNDS.TERRIBLE,
        garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG,
        garak.analyze.RELATIVE_DEFCON_BOUNDS.ABOVE_AVG,
        garak.analyze.RELATIVE_DEFCON_BOUNDS.EXCELLENT,
    ],
)
def test_defcon_and_comment_compatibility_shim(zscore):
    calibration = garak.analyze.calibration.Calibration.__new__(
        garak.analyze.calibration.Calibration
    )
    expected_defcon = garak.analyze.score_to_defcon(
        zscore, garak.analyze.RELATIVE_DEFCON_BOUNDS
    )

    defcon, comment = calibration.defcon_and_comment(zscore)

    assert defcon == expected_defcon, "shim should use relative defcon boundaries"
    assert (
        comment == garak.analyze.RELATIVE_COMMENT[expected_defcon]
    ), "shim should return the relative risk comment"
