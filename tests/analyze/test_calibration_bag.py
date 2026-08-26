from collections import Counter
from pathlib import Path

import pytest
import yaml

from docs.source._ext import calibration_data
from docs.source._ext.calibration_data import (
    BagModel,
    CALIBRATION_ARCHIVE,
    CALIBRATION_ROOT,
    CalibrationBag,
    CURRENT_BAG_CONFIG,
    CURRENT_BAG_DATA,
    _load_bag_models,
    _map_reports_to_bag,
    _resolve_within,
    _validate_report_input,
    archived_calibration_releases,
    current_calibration_release,
    report_target,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOC_SOURCE = REPOSITORY_ROOT / "docs" / "source" / "reporting.calibration.rst"


def test_calibration_bag_has_one_current_source_and_a_frozen_archive():
    current_release = current_calibration_release()
    archived_releases = archived_calibration_releases()
    archived_bags = {
        release.bag.bag_id: release.bag
        for release in archived_releases
        if release.bag is not None and not release.bag.current
    }

    assert (
        CURRENT_BAG_DATA.is_file()
    ), f"missing canonical model-bag data: {CURRENT_BAG_DATA}"
    assert (
        CURRENT_BAG_CONFIG.is_file()
    ), f"missing canonical model-bag config: {CURRENT_BAG_CONFIG}"
    assert current_release.current, "the calibration pointer must identify current data"
    assert (
        current_release.bag is not None and current_release.bag.current
    ), "the current calibration must resolve the canonical model bag"
    assert archived_bags, "the calibration archive must contain a frozen model bag"
    assert not (
        CALIBRATION_ROOT / "bags"
    ).exists(), "the plural bags layout duplicates the canonical current model bag"
    assert (
        current_release.bag.bag_id not in archived_bags
    ), "the current model bag must not be duplicated in the archive"
    assert all(
        bag.bag_path.parent.parent == CALIBRATION_ARCHIVE
        for bag in archived_bags.values()
    ), "frozen model-bag data must remain under the calibration archive"


def test_reference_sources_cover_every_versioned_calibration():
    releases = [current_calibration_release(), *archived_calibration_releases()]
    discovered_paths = {
        release.calibration_path.resolve(strict=True) for release in releases
    }
    versioned_paths = {
        path.resolve(strict=True)
        for path in CALIBRATION_ROOT.glob("calibration-*.json")
    }

    assert (
        discovered_paths == versioned_paths
    ), "the generated reference must include every versioned calibration file"
    assert len({release.release_id for release in releases}) == len(
        releases
    ), "calibration release IDs must be unique"

    for release in releases:
        assert (
            release.report_inputs
        ), f"release {release.release_id} must record report inputs"
        if release.bag is not None:
            if release.release_id == release.bag.bag_id:
                assert len(release.bag.models) == len(release.report_inputs), (
                    f"provenance calibration {release.release_id} must map every "
                    "model-bag entry"
                )
            config = yaml.safe_load(release.bag.config)
            assert isinstance(
                config, dict
            ), f"config for model bag {release.bag.bag_id} must be a mapping"
            assert {"system", "run", "plugins"} <= set(
                config
            ), f"config for model bag {release.bag.bag_id} must contain core sections"


def test_calibration_rerun_reuses_one_archived_model_bag():
    releases = {
        release.release_id: release for release in archived_calibration_releases()
    }
    rerun = releases["2024-09update"]

    assert rerun.bag is not None
    assert rerun.bag.bag_id == "2024-summer"
    assert len(rerun.report_inputs) == 26
    assert len(rerun.bag.models) == 13
    mapped_targets = _map_reports_to_bag(
        rerun.report_inputs, rerun.bag, rerun.calibration_path
    )
    assert set(Counter(mapped_targets).values()) == {2}

    invalid_inputs = (*rerun.report_inputs[:-1], "unrelated.report.jsonl")
    with pytest.raises(ValueError, match="does not match model bag"):
        _map_reports_to_bag(invalid_inputs, rerun.bag, rerun.calibration_path)

    prefix_smuggled_inputs = (
        *rerun.report_inputs,
        "mistral-nemo-12b-instruct_unrelated.report.jsonl",
    )
    with pytest.raises(ValueError, match="does not cover model bag"):
        _map_reports_to_bag(prefix_smuggled_inputs, rerun.bag, rerun.calibration_path)


def test_reused_bag_mapping_preserves_provider_path_identity(tmp_path):
    models = tuple(
        BagModel(
            provider=provider,
            model="shared-model",
            parameters_billions="1",
            report_input=f"{provider}/shared-model.report.jsonl",
            source_url=f"https://example.com/{provider}/shared-model",
            notes="Test metadata.",
        )
        for provider in ("provider-one", "provider-two")
    )
    bag = CalibrationBag(
        bag_id="test-bag",
        models=models,
        bag_path=tmp_path / "bag.csv",
        config="system: {}\n",
        config_path=tmp_path / "config.yaml",
    )
    report_inputs = tuple(
        f"{provider}/shared-model_rerun.report.jsonl"
        for provider in ("provider-one", "provider-two")
    )

    assert set(_map_reports_to_bag(report_inputs, bag, Path("calibration.json"))) == {
        "provider-one/shared-model.report.jsonl",
        "provider-two/shared-model.report.jsonl",
    }
    with pytest.raises(ValueError, match="does not cover model bag"):
        _map_reports_to_bag(report_inputs[:1], bag, Path("calibration.json"))


def test_reused_bag_mapping_validates_directory_style_variants(tmp_path):
    model = BagModel(
        provider="provider",
        model="shared-model",
        parameters_billions="1",
        report_input="reports/shared-model/report.jsonl",
        source_url="https://example.com/provider/shared-model",
        notes="Test metadata.",
    )
    bag = CalibrationBag(
        bag_id="test-bag",
        models=(model,),
        bag_path=tmp_path / "bag.csv",
        config="system: {}\n",
        config_path=tmp_path / "config.yaml",
    )

    assert _map_reports_to_bag(
        ("reports/shared-model_rerun/report.jsonl",),
        bag,
        Path("calibration.json"),
    ) == ("reports/shared-model/report.jsonl",)
    with pytest.raises(ValueError, match="invalid report variant"):
        _map_reports_to_bag(
            ("reports/shared-model__bad/report.jsonl",),
            bag,
            Path("calibration.json"),
        )


def test_size_categories_are_derived_from_parameter_count():
    known = BagModel(
        provider="provider",
        model="model",
        parameters_billions="100",
        report_input="model.report.jsonl",
        source_url="https://example.com/model",
        notes="Test metadata.",
    )
    unknown = BagModel(
        provider="provider",
        model="model",
        parameters_billions="NA",
        report_input="model.report.jsonl",
        source_url="https://example.com/model",
        notes="Test metadata.",
    )

    assert known.size_categories == ("2", "6")
    assert unknown.size_categories == ("NA", "NA")


def test_report_inputs_accept_windows_paths_without_losing_exact_source_text():
    report_input = r"C:\calibration\example-model\report.jsonl"

    assert _validate_report_input(report_input, Path("test-data")) == report_input
    assert report_target(report_input) == "example-model"


def test_model_bag_sources_reject_symlinks(tmp_path):
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    outside_file = tmp_path / "outside-config.yaml"
    outside_file.write_text("secret: value\n", encoding="utf-8")
    linked_config = archive_root / "config.yaml"
    try:
        linked_config.symlink_to(outside_file)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable on this platform: {error}")

    with pytest.raises(ValueError, match="must not be a symlink"):
        _resolve_within(linked_config, archive_root, "model-bag config")


def test_model_bag_csv_rejects_unquoted_extra_fields(tmp_path):
    bag_path = tmp_path / "bag.csv"
    bag_path.write_text(
        "report_input,provider,model,parameters_billions,source_url,notes\n"
        "model.report.jsonl,provider,model,1,https://example.com,first,second\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unexpected extra fields"):
        _load_bag_models(bag_path, tmp_path, ("model.report.jsonl",))


def test_model_bag_archive_rejects_symlinked_root(tmp_path, monkeypatch):
    real_archive = tmp_path / "real-archive"
    real_archive.mkdir()
    linked_archive = tmp_path / "archive"
    try:
        linked_archive.symlink_to(real_archive, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable on this platform: {error}")

    monkeypatch.setattr(calibration_data, "CALIBRATION_ARCHIVE", linked_archive)
    with pytest.raises(ValueError, match="must be a regular directory"):
        calibration_data._archived_bag_sources("current-bag")


def test_calibration_reference_is_generated_instead_of_hard_coded():
    releases = [current_calibration_release(), *archived_calibration_releases()]
    documentation = DOC_SOURCE.read_text(encoding="utf-8")

    assert documentation.count(".. calibration-data:: current") == 1
    assert documentation.count(".. calibration-data:: archive") == 1
    assert ".. csv-table::" not in documentation
    assert "/calibration/bags" not in documentation
    for release in releases:
        assert f"Calibration ``{release.release_id}``" not in documentation, (
            "release-specific documentation must be generated from calibration "
            f"source data, but {release.release_id} is hard coded"
        )
