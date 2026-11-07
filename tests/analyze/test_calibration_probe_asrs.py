import json

import pytest

from garak.analyze.calibration import Calibration


def test_get_probe_asrs_converts_pass_rates(tmp_path):
    calibration_path = tmp_path / "calibration.json"
    calibration_path.write_text(
        json.dumps(
            {
                "alpha.First/detector.HighPass": {"mu": 0.8},
                "alpha.First/detector.LowPass": {"mu": 0.25},
                "alpha.Second/detector.Other": {"mu": 0.1},
            }
        ),
        encoding="utf-8",
    )

    calibration = Calibration(calibration_path)

    assert calibration.get_probe_asrs("probes.alpha.First") == pytest.approx(
        [0.2, 0.75]
    ), "pass rates should be converted to attack success rates"
    assert (
        calibration.get_probe_asrs("alpha.Missing") == []
    ), "unknown probes should have no calibrated attack success rates"


def test_get_probe_asrs_without_loaded_calibration():
    calibration = Calibration("missing-calibration.json")

    assert (
        calibration.get_probe_asrs("probes.alpha.First") == []
    ), "failed calibration loads should return no attack success rates"
