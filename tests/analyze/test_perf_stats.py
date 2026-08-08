import json

import pytest

from garak.analyze import perf_stats


@pytest.fixture
def calibration_report(tmp_path):
    report_path = tmp_path / "target.report.jsonl"
    records = [
        {
            "entry_type": "eval",
            "probe": "probe.Test",
            "detector": "detector.Test",
            "passed": passed,
            "total_evaluated": 2,
        }
        for passed in (0, 1, 2)
    ]
    report_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
    return str(report_path)


def test_build_score_dict_records_model_bag_id(calibration_report):
    result = perf_stats.build_score_dict([calibration_report], bag_id="2026-02")

    assert result["garak_calibration_meta"]["bag"] == "2026-02"
    assert result["garak_calibration_meta"]["filenames"] == [calibration_report]


def test_build_score_dict_records_null_without_model_bag(calibration_report):
    result = perf_stats.build_score_dict([calibration_report])

    assert (
        result["garak_calibration_meta"]["bag"] is None
    ), "calibrations without a model-bag snapshot must record an explicit null"


@pytest.mark.parametrize("bag_id", ["", "Bad ID", "../archive", 202602])
def test_build_score_dict_rejects_invalid_model_bag_id(bag_id):
    with pytest.raises(ValueError, match="invalid model-bag ID"):
        perf_stats.build_score_dict([], bag_id=bag_id)


def test_main_passes_model_bag_id_to_calibration_builder(monkeypatch):
    received = {}

    def fake_build_score_dict(filenames, bag_id=None):
        received["filenames"] = filenames
        received["bag_id"] = bag_id
        return {"garak_calibration_meta": {"bag": bag_id}}

    monkeypatch.setattr(perf_stats, "build_score_dict", fake_build_score_dict)
    monkeypatch.setattr(perf_stats._config, "load_config", lambda: None)
    monkeypatch.setattr(perf_stats.sys.stdout, "reconfigure", lambda **_: None)

    perf_stats.main(["--bag-id", "2026-02", "target.report.jsonl"])

    assert received == {
        "filenames": ["target.report.jsonl"],
        "bag_id": "2026-02",
    }


def test_main_reports_invalid_model_bag_id_as_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(perf_stats._config, "load_config", lambda: None)

    with pytest.raises(SystemExit) as error:
        perf_stats.main(["--bag-id", "Bad ID", "target.report.jsonl"])

    assert error.value.code == 2
    assert "invalid model-bag ID" in capsys.readouterr().err
