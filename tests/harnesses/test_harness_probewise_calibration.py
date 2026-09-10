import json

import pytest

from garak import _config
from garak.harnesses.probewise import ProbewiseHarness


@pytest.fixture
def harness(mocker):
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    _config.load_base_config()
    return ProbewiseHarness()


@pytest.fixture
def calibration_path(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(
        json.dumps(
            {
                "alpha.First/detector.One": {"mu": 0.8},
                "beta.Second/detector.One": {"mu": 0.6},
                "beta.Second/detector.Two": {"mu": 0.1},
                "delta.Fourth/detector.One": {"mu": 0.5},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_alphabetical_probe_order(harness):
    harness.probe_order = "alphabetical"
    probes = ["probes.beta.Second", "probes.alpha.First"]

    assert harness._order_probes(probes) == [
        "probes.alpha.First",
        "probes.beta.Second",
    ], "alphabetical probe ordering should sort plugin names"


def test_calibration_order_loads_from_harness_config(mocker, calibration_path):
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    _config.load_base_config()
    _config.plugins.harnesses["probewise"] = {
        "probe_order": "calibration",
        "calibration_path": calibration_path,
    }

    configured_harness = ProbewiseHarness()

    assert configured_harness._order_probes(
        ["probes.delta.Fourth", "probes.beta.Second"]
    ) == [
        "probes.beta.Second",
        "probes.delta.Fourth",
    ], "harness configuration should enable calibration ordering"


@pytest.mark.parametrize(
    ("aggregation", "expected"),
    [
        (
            "max",
            [
                "probes.beta.Second",
                "probes.delta.Fourth",
                "probes.alpha.First",
            ],
        ),
        (
            "mean",
            [
                "probes.beta.Second",
                "probes.delta.Fourth",
                "probes.alpha.First",
            ],
        ),
        (
            "median",
            [
                "probes.beta.Second",
                "probes.delta.Fourth",
                "probes.alpha.First",
            ],
        ),
        (
            "min",
            [
                "probes.delta.Fourth",
                "probes.beta.Second",
                "probes.alpha.First",
            ],
        ),
    ],
)
def test_calibration_order_aggregates_detector_asrs(
    harness, calibration_path, aggregation, expected
):
    harness.probe_order = "calibration"
    harness.calibration_path = calibration_path
    harness.calibration_aggregation = aggregation
    probes = [
        "probes.alpha.First",
        "probes.beta.Second",
        "probes.delta.Fourth",
    ]

    assert (
        harness._order_probes(probes) == expected
    ), f"{aggregation} should aggregate detector attack success rates"


@pytest.mark.parametrize(
    ("uncalibrated_score", "expected_position"), [(1.0, 0), (0.0, 2), (0.3, 1)]
)
def test_uncalibrated_score_places_unknown_probes(
    harness, calibration_path, uncalibrated_score, expected_position
):
    harness.probe_order = "calibration"
    harness.calibration_path = calibration_path
    harness.uncalibrated_score = uncalibrated_score
    probes = [
        "probes.alpha.First",
        "probes.gamma.Third",
        "probes.delta.Fourth",
    ]

    ordered = harness._order_probes(probes)

    assert (
        ordered.index("probes.gamma.Third") == expected_position
    ), "uncalibrated score should control unknown probe placement"


def test_skip_uncalibrated_probes_logs_omissions(harness, calibration_path, caplog):
    harness.probe_order = "calibration"
    harness.calibration_path = calibration_path
    harness.skip_uncalibrated_probes = True
    probes = ["probes.alpha.First", "probes.gamma.Third"]

    ordered = harness._order_probes(probes)

    assert ordered == [
        "probes.alpha.First"
    ], "uncalibrated probes should be omitted when configured"
    assert (
        "probes.gamma.Third" in caplog.text
    ), "omitted probes should be recorded in the log"


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("probe_order", "random", "probe_order"),
        ("calibration_aggregation", "mode", "calibration_aggregation"),
        ("uncalibrated_score", -0.1, "uncalibrated_score"),
        ("uncalibrated_score", 1.1, "uncalibrated_score"),
        ("skip_uncalibrated_probes", "yes", "skip_uncalibrated_probes"),
    ],
)
def test_invalid_calibration_order_config_is_rejected(
    harness, calibration_path, attribute, value, message
):
    harness.probe_order = "calibration"
    harness.calibration_path = calibration_path
    setattr(harness, attribute, value)

    with pytest.raises(ValueError, match=message):
        harness._order_probes(["probes.alpha.First"])


def test_missing_calibration_file_is_rejected(harness, tmp_path):
    harness.probe_order = "calibration"
    harness.calibration_path = tmp_path / "missing.json"

    with pytest.raises(ValueError, match="Unable to load calibration data"):
        harness._order_probes(["probes.alpha.First"])
