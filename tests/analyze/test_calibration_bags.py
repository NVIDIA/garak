import csv
from pathlib import Path

import yaml

CALIBRATION_ROOT = Path("garak/data/calibration")
CATALOG_PATH = CALIBRATION_ROOT / "bags" / "index.yaml"
MODEL_FIELDS = [
    "decimal size category",
    "binary size category",
    "provider",
    "model",
    "parameters (billions)",
]


def _resolve_catalog_path(relative_path: str) -> Path:
    candidate = (CALIBRATION_ROOT / relative_path).resolve()
    assert candidate.is_relative_to(
        CALIBRATION_ROOT.resolve()
    ), f"calibration catalog path escapes its data directory: {relative_path}"
    return candidate


def test_calibration_bag_catalog_references_valid_release_data():
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))

    assert set(catalog) == {"current", "releases"}
    assert catalog["releases"], "calibration bag catalog must include a release"

    release_ids = [release["id"] for release in catalog["releases"]]
    assert len(release_ids) == len(set(release_ids)), "release IDs must be unique"
    assert catalog["current"] in release_ids

    for release in catalog["releases"]:
        assert {"id", "title", "calibration", "models", "config"} <= set(release)

        calibration_path = _resolve_catalog_path(release["calibration"])
        models_path = _resolve_catalog_path(release["models"])
        config_path = _resolve_catalog_path(release["config"])

        assert calibration_path.is_file(), f"missing calibration: {calibration_path}"
        assert models_path.is_file(), f"missing model bag: {models_path}"
        assert config_path.is_file(), f"missing run config: {config_path}"

        with models_path.open(encoding="utf-8", newline="") as models_file:
            rows = list(csv.DictReader(models_file))

        assert rows, f"model bag must not be empty: {models_path}"
        assert list(rows[0]) == MODEL_FIELDS

        model_keys = {(row["provider"], row["model"]) for row in rows}
        assert len(model_keys) == len(rows), f"duplicate model in {models_path}"

        for row in rows:
            assert row["provider"].strip(), f"provider is required in {models_path}"
            assert row["model"].strip(), f"model is required in {models_path}"
            for field in ("decimal size category", "binary size category"):
                value = row[field].strip()
                assert (
                    value in {"", "NA"} or value.isdecimal()
                ), f"invalid {field} value {value!r} in {models_path}"
            parameter_count = row["parameters (billions)"].strip()
            assert parameter_count == "NA" or float(parameter_count) > 0

        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert set(config) >= {"system", "run", "plugins"}


def test_current_calibration_matches_catalog_pointer():
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    current_release = next(
        release
        for release in catalog["releases"]
        if release["id"] == catalog["current"]
    )

    current_calibration = (CALIBRATION_ROOT / "calibration.json").resolve()
    catalog_calibration = _resolve_catalog_path(current_release["calibration"])

    assert current_calibration == catalog_calibration
