"""Load and render the model-bag data used by the calibration reference."""

import csv
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import math
from pathlib import Path, PurePosixPath
import re

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CALIBRATION_ROOT = REPOSITORY_ROOT / "garak" / "data" / "calibration"
CALIBRATION_POINTER = CALIBRATION_ROOT / "calibration.json"
CURRENT_BAG_DATA = CALIBRATION_ROOT / "bag.csv"
CURRENT_BAG_CONFIG = REPOSITORY_ROOT / "garak" / "configs" / "bag.yaml"
CALIBRATION_ARCHIVE = CALIBRATION_ROOT / "archive"

_CALIBRATION_FILENAME = re.compile(
    r"calibration-(?P<release>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.json"
)
_CALIBRATION_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_REPORT_SUFFIX = ".report.jsonl"
_REPORT_VARIANT_SUFFIX = re.compile(r"_[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?")
_BAG_FIELDS = [
    "report_input",
    "provider",
    "model",
    "parameters_billions",
    "source_url",
    "notes",
]


@dataclass(frozen=True)
class BagModel:
    """One model and its exact report input in a calibration bag."""

    provider: str
    model: str
    parameters_billions: str
    report_input: str
    source_url: str
    notes: str

    @property
    def size_categories(self) -> tuple[str, str]:
        """Return decimal and binary order-of-magnitude categories."""
        return _size_categories(self.parameters_billions)


@dataclass(frozen=True)
class CalibrationBag:
    """One canonical or archived model bag and its provenance data."""

    bag_id: str
    models: tuple[BagModel, ...]
    bag_path: Path
    config: str
    config_path: Path
    current: bool = False

    @property
    def dependencies(self) -> tuple[Path, ...]:
        """Return files that must invalidate an incremental docs build."""
        return self.bag_path, self.config_path


@dataclass(frozen=True)
class CalibrationRelease:
    """Validated source data for one versioned calibration."""

    release_id: str
    generated_at: str
    report_inputs: tuple[str, ...]
    calibration_path: Path
    bag: CalibrationBag | None = None
    current: bool = False

    @property
    def dependencies(self) -> tuple[Path, ...]:
        """Return files that must invalidate an incremental docs build."""
        paths = [self.calibration_path]
        if self.bag is not None:
            paths.extend(self.bag.dependencies)
        return tuple(paths)


def _release_id(calibration_path: Path) -> str:
    match = _CALIBRATION_FILENAME.fullmatch(calibration_path.name)
    if match is None:
        raise ValueError(
            "calibration data must use a calibration-<release>.json filename: "
            f"{calibration_path.name}"
        )
    return match.group("release")


def _resolve_within(path: Path, root: Path, description: str) -> Path:
    """Resolve a regular file contained by the expected root."""
    if path.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {path}")
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if not resolved_path.is_file() or not resolved_path.is_relative_to(resolved_root):
        raise ValueError(f"{description} must be a file inside {root}: {path}")
    return resolved_path


def resolve_current_calibration() -> Path:
    """Resolve calibration.json as either a symlink or a Git text pointer."""
    if CALIBRATION_POINTER.is_symlink():
        calibration_path = CALIBRATION_POINTER.resolve(strict=True)
    else:
        pointer_value = CALIBRATION_POINTER.read_text(encoding="utf-8").strip()
        if not pointer_value or "\n" in pointer_value or "\r" in pointer_value:
            raise ValueError(
                "calibration.json must point to one versioned calibration file"
            )
        calibration_path = (CALIBRATION_ROOT / pointer_value).resolve(strict=True)

    calibration_root = CALIBRATION_ROOT.resolve(strict=True)
    if calibration_path.parent != calibration_root:
        raise ValueError("calibration.json must resolve inside garak/data/calibration")
    _release_id(calibration_path)
    return calibration_path


def _normalise_report_input(report_input: str) -> str:
    """Normalise separators for comparison while preserving source text."""
    return report_input.replace("\\", "/").casefold()


def _validate_report_input(report_input: object, source: Path) -> str:
    if not isinstance(report_input, str) or not report_input:
        raise ValueError(f"report inputs in {source} must be non-empty strings")
    if any(character in report_input for character in ("`", "\n", "\r")):
        raise ValueError(f"report input cannot be rendered safely: {report_input!r}")

    report_path = PurePosixPath(report_input.replace("\\", "/"))
    if report_path.name == "report.jsonl":
        if len(report_path.parts) < 2:
            raise ValueError(
                f"report input does not identify a target: {report_input!r}"
            )
    elif (
        not report_path.name.endswith(_REPORT_SUFFIX)
        or report_path.name == _REPORT_SUFFIX
    ):
        raise ValueError(
            f"report input must end in {_REPORT_SUFFIX} or /report.jsonl: "
            f"{report_input!r}"
        )
    return report_input


def report_target(report_input: str) -> str:
    """Derive a model name from an exact calibration report path."""
    report_path = PurePosixPath(report_input.replace("\\", "/"))
    if report_path.name == "report.jsonl":
        return report_path.parent.name
    return report_path.name.removesuffix(_REPORT_SUFFIX)


def _report_identity(report_input: str) -> tuple[tuple[str, ...], str, str]:
    """Return the path scope, target, and layout of a report input."""
    report_path = PurePosixPath(_normalise_report_input(report_input))
    if report_path.name == "report.jsonl":
        return report_path.parent.parent.parts, report_path.parent.name, "directory"
    return (
        report_path.parent.parts,
        report_path.name.removesuffix(_REPORT_SUFFIX),
        "file",
    )


def _validate_rst_text(value: object, field: str, source: Path) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} in {source} must be a non-empty trimmed string")
    if any(character in value for character in ("`", "\n", "\r")):
        raise ValueError(f"{field} in {source} cannot contain RST control characters")
    return value


def _size_categories(parameters_billions: str) -> tuple[str, str]:
    if parameters_billions == "NA":
        return "NA", "NA"
    try:
        parameter_count = Decimal(parameters_billions)
    except InvalidOperation as error:
        raise ValueError(f"invalid parameter count: {parameters_billions!r}") from error
    if not parameter_count.is_finite() or parameter_count <= 0:
        raise ValueError(f"parameter count must be positive: {parameters_billions!r}")
    numeric_count = float(parameter_count)
    return str(math.floor(math.log10(numeric_count))), str(
        math.floor(math.log2(numeric_count))
    )


def _load_calibration_metadata(
    calibration_path: Path,
) -> tuple[str, tuple[str, ...], str | None]:
    resolved_path = _resolve_within(
        calibration_path, CALIBRATION_ROOT, "calibration data"
    )
    with resolved_path.open(encoding="utf-8") as calibration_file:
        calibration = json.load(calibration_file)
    metadata = calibration.get("garak_calibration_meta")
    if not isinstance(metadata, dict):
        raise ValueError(f"missing garak_calibration_meta in {calibration_path}")

    if "bag" not in metadata:
        raise ValueError(f"missing model-bag ID in {calibration_path}")
    bag_id = metadata["bag"]
    if bag_id is not None and (
        not isinstance(bag_id, str)
        or _CALIBRATION_FILENAME.fullmatch(f"calibration-{bag_id}.json") is None
    ):
        raise ValueError(f"invalid model-bag ID in {calibration_path}: {bag_id!r}")

    generated_at = metadata.get("date")
    if (
        not isinstance(generated_at, str)
        or not generated_at.strip()
        or _CALIBRATION_DATE.match(generated_at) is None
        or any(character in generated_at for character in ("`", "\n", "\r"))
    ):
        raise ValueError(f"invalid calibration date in {calibration_path}")

    raw_report_inputs = metadata.get("filenames")
    if not isinstance(raw_report_inputs, list) or not raw_report_inputs:
        raise ValueError(f"missing report inputs in {calibration_path}")
    report_inputs = tuple(
        _validate_report_input(report_input, calibration_path)
        for report_input in raw_report_inputs
    )
    normalised_inputs = {
        _normalise_report_input(report_input) for report_input in report_inputs
    }
    if len(normalised_inputs) != len(report_inputs):
        raise ValueError(f"duplicate report inputs in {calibration_path}")
    return generated_at, report_inputs, bag_id


def _load_bag_models(
    bag_path: Path, bag_root: Path, report_inputs: tuple[str, ...]
) -> tuple[BagModel, ...]:
    resolved_path = _resolve_within(bag_path, bag_root, "model-bag data")
    with resolved_path.open(encoding="utf-8", newline="") as bag_file:
        reader = csv.DictReader(bag_file)
        if reader.fieldnames != _BAG_FIELDS:
            raise ValueError(
                f"model-bag fields in {bag_path} must be {_BAG_FIELDS}, "
                f"got {reader.fieldnames}"
            )
        rows = list(reader)
    if not rows:
        raise ValueError(f"model-bag data must not be empty: {bag_path}")

    models = []
    for row_number, row in enumerate(rows, start=2):
        if None in row:
            raise ValueError(
                f"unexpected extra fields in {bag_path} on row {row_number}"
            )
        provider = _validate_rst_text(row.get("provider"), "provider", bag_path)
        model = _validate_rst_text(row.get("model"), "model", bag_path)
        parameters = _validate_rst_text(
            row.get("parameters_billions"), "parameters_billions", bag_path
        )
        source_url = _validate_rst_text(row.get("source_url"), "source_url", bag_path)
        if not source_url.startswith("https://"):
            raise ValueError(f"source_url in {bag_path} must use HTTPS")
        notes = _validate_rst_text(row.get("notes"), "notes", bag_path)
        _size_categories(parameters)
        report_input = _validate_report_input(row.get("report_input"), bag_path)
        if model.casefold() != report_target(report_input).casefold():
            raise ValueError(
                f"model {model!r} does not match report input {report_input!r} "
                f"in {bag_path}"
            )
        models.append(
            BagModel(
                provider=provider,
                model=model,
                parameters_billions=parameters,
                report_input=report_input,
                source_url=source_url,
                notes=notes,
            )
        )

    report_keys = {_normalise_report_input(item) for item in report_inputs}
    model_report_keys = {
        _normalise_report_input(model.report_input) for model in models
    }
    if len(model_report_keys) != len(models):
        raise ValueError(f"duplicate report inputs in {bag_path}")
    if report_keys != model_report_keys:
        missing = len(report_keys - model_report_keys)
        extra = len(model_report_keys - report_keys)
        raise ValueError(
            f"model-bag data does not match calibration report inputs in {bag_path}: "
            f"{missing} missing, {extra} extra"
        )

    model_keys = {
        (model.provider.casefold(), model.model.casefold()) for model in models
    }
    if len(model_keys) != len(models):
        raise ValueError(f"duplicate provider/model entries in {bag_path}")
    return tuple(models)


def _load_bag(
    bag_id: str,
    bag_path: Path,
    config_path: Path,
    *,
    bag_root: Path,
    config_root: Path,
    current: bool = False,
) -> CalibrationBag:
    provenance_path = CALIBRATION_ROOT / f"calibration-{bag_id}.json"
    _, report_inputs, declared_bag_id = _load_calibration_metadata(provenance_path)
    if declared_bag_id != bag_id:
        raise ValueError(
            f"model bag {bag_id} must reference itself in {provenance_path}"
        )

    models = _load_bag_models(bag_path, bag_root, report_inputs)
    resolved_config = _resolve_within(config_path, config_root, "model-bag config")
    config = resolved_config.read_text(encoding="utf-8")
    if not config.strip():
        raise ValueError(f"empty model-bag config: {config_path}")
    return CalibrationBag(
        bag_id=bag_id,
        models=models,
        bag_path=bag_path,
        config=config,
        config_path=config_path,
        current=current,
    )


def _map_reports_to_bag(
    report_inputs: tuple[str, ...],
    bag: CalibrationBag,
    calibration_path: Path,
) -> tuple[str, ...]:
    """Map complete report-variant cohorts to canonical bag report inputs."""
    bag_reports = {
        _normalise_report_input(model.report_input): _report_identity(
            model.report_input
        )
        for model in bag.models
    }
    if len(bag_reports) != len(bag.models):
        raise ValueError(f"duplicate report inputs in model bag {bag.bag_id}")

    mapped_reports = []
    variant_cohorts: dict[str, set[str]] = {}
    for report_input in report_inputs:
        scope, target, layout = _report_identity(report_input)
        candidates = [
            (bag_report, bag_target)
            for bag_report, (bag_scope, bag_target, bag_layout) in bag_reports.items()
            if scope == bag_scope
            and layout == bag_layout
            and (target == bag_target or target.startswith(f"{bag_target}_"))
        ]
        if not candidates:
            raise ValueError(
                f"report input {report_input!r} in {calibration_path} does not "
                f"match model bag {bag.bag_id}"
            )
        bag_report, bag_target = max(candidates, key=lambda item: len(item[1]))
        variant_suffix = target.removeprefix(bag_target)
        if variant_suffix and _REPORT_VARIANT_SUFFIX.fullmatch(variant_suffix) is None:
            raise ValueError(
                f"invalid report variant {report_input!r} in {calibration_path}"
            )
        variant_cohorts.setdefault(variant_suffix, set()).add(bag_report)
        mapped_reports.append(bag_report)

    bag_report_set = set(bag_reports)
    for variant_suffix, cohort in variant_cohorts.items():
        missing_reports = bag_report_set - cohort
        if not missing_reports:
            continue
        variant_label = variant_suffix or "<base>"
        missing_list = ", ".join(sorted(missing_reports))
        raise ValueError(
            f"calibration {calibration_path} report variant {variant_label!r} does "
            f"not cover model bag {bag.bag_id}: missing {missing_list}"
        )

    if not variant_cohorts:
        raise ValueError(
            f"calibration {calibration_path} does not cover model bag {bag.bag_id}"
        )
    return tuple(mapped_reports)


def _load_release(
    calibration_path: Path,
    bags: dict[str, CalibrationBag],
    *,
    current: bool = False,
) -> CalibrationRelease:
    release_id = _release_id(calibration_path)
    generated_at, report_inputs, bag_id = _load_calibration_metadata(calibration_path)
    if bag_id is not None and bag_id not in bags:
        raise ValueError(
            f"calibration {release_id} references unavailable model bag {bag_id}"
        )
    bag = bags.get(bag_id)
    if bag is not None and release_id != bag.bag_id:
        _map_reports_to_bag(report_inputs, bag, calibration_path)
    return CalibrationRelease(
        release_id=release_id,
        generated_at=generated_at,
        report_inputs=report_inputs,
        calibration_path=calibration_path,
        bag=bag,
        current=current,
    )


def current_calibration_release() -> CalibrationRelease:
    """Load the one canonical current model bag and calibration."""
    calibration_path = resolve_current_calibration()
    _, _, bag_id = _load_calibration_metadata(calibration_path)
    if bag_id is None:
        raise ValueError("the current calibration must identify its model bag")
    bag = _load_bag(
        bag_id,
        CURRENT_BAG_DATA,
        CURRENT_BAG_CONFIG,
        bag_root=CALIBRATION_ROOT,
        config_root=CURRENT_BAG_CONFIG.parent,
        current=True,
    )
    return _load_release(calibration_path, {bag_id: bag}, current=True)


def _archived_bag_sources(current_bag_id: str) -> dict[str, tuple[Path, Path]]:
    if CALIBRATION_ARCHIVE.is_symlink() or not CALIBRATION_ARCHIVE.is_dir():
        raise ValueError(
            f"calibration archive must be a regular directory: {CALIBRATION_ARCHIVE}"
        )

    resolved_archive = CALIBRATION_ARCHIVE.resolve(strict=True)
    sources = {}
    for release_directory in sorted(
        path for path in CALIBRATION_ARCHIVE.iterdir() if path.is_dir()
    ):
        if release_directory.is_symlink():
            raise ValueError(
                f"calibration archive directory must not be a symlink: "
                f"{release_directory}"
            )
        resolved_directory = release_directory.resolve(strict=True)
        if not resolved_directory.is_relative_to(resolved_archive):
            raise ValueError(
                f"calibration archive directory escapes its root: {release_directory}"
            )
        bag_id = release_directory.name
        if _CALIBRATION_FILENAME.fullmatch(f"calibration-{bag_id}.json") is None:
            raise ValueError(f"invalid archived model-bag ID: {bag_id}")
        if bag_id == current_bag_id:
            raise ValueError(
                f"current model bag {bag_id} must not be duplicated in the archive"
            )
        sources[bag_id] = (
            release_directory / "bag.csv",
            release_directory / "config.yaml",
        )
    return sources


def archived_calibration_releases() -> list[CalibrationRelease]:
    """Discover every historical calibration and any frozen bag snapshot."""
    current_release = current_calibration_release()
    current_path = current_release.calibration_path.resolve(strict=True)
    current_bag = current_release.bag
    if current_bag is None:
        raise ValueError("the current calibration must identify its model bag")

    bag_sources = _archived_bag_sources(current_bag.bag_id)
    bags = {current_bag.bag_id: current_bag}
    for bag_id, (bag_path, config_path) in bag_sources.items():
        bags[bag_id] = _load_bag(
            bag_id,
            bag_path,
            config_path,
            bag_root=bag_path.parent,
            config_root=config_path.parent,
        )

    releases = []
    referenced_bag_ids = set()

    for calibration_path in sorted(CALIBRATION_ROOT.glob("calibration-*.json")):
        if calibration_path.resolve(strict=True) == current_path:
            continue
        release = _load_release(calibration_path, bags)
        releases.append(release)
        if release.bag is not None:
            referenced_bag_ids.add(release.bag.bag_id)

    unreferenced_bags = set(bag_sources) - referenced_bag_ids
    if unreferenced_bags:
        bag_list = ", ".join(sorted(unreferenced_bags))
        raise ValueError(
            f"archived model bags are not referenced by a calibration: {bag_list}"
        )
    if not releases:
        raise ValueError(f"no historical calibrations found in {CALIBRATION_ROOT}")
    return sorted(
        releases,
        key=lambda release: (release.generated_at, release.release_id),
        reverse=True,
    )


def _repository_path(path: Path) -> str:
    return path.relative_to(REPOSITORY_ROOT).as_posix()


def _render_model_table(models: tuple[BagModel, ...]) -> list[str]:
    lines = [
        ".. list-table:: Model bag",
        "   :header-rows: 1",
        "   :widths: 10 10 18 45 17",
        "",
        "   * - 10^n category",
        "     - 2^n category",
        "     - Provider",
        "     - Model",
        "     - Parameters (B)",
    ]
    for model in sorted(
        models, key=lambda item: (item.provider.casefold(), item.model.casefold())
    ):
        decimal_category, binary_category = model.size_categories
        lines.extend(
            [
                f"   * - ``{decimal_category}``",
                f"     - ``{binary_category}``",
                f"     - ``{model.provider}``",
                f"     - `{model.model} <{model.source_url}>`__",
                f"     - ``{model.parameters_billions}``",
            ]
        )
    return lines


def _render_report_table(report_inputs: tuple[str, ...]) -> list[str]:
    lines = [
        ".. list-table:: Report inputs",
        "   :header-rows: 1",
        "   :widths: 35 65",
        "",
        "   * - Target",
        "     - Source report",
    ]
    for report_input in sorted(report_inputs, key=str.casefold):
        lines.extend(
            [
                f"   * - ``{report_target(report_input)}``",
                f"     - ``{report_input}``",
            ]
        )
    return lines


def render_calibration_release(release: CalibrationRelease) -> str:
    """Render one release from validated source data as reStructuredText."""
    current_label = " (current)" if release.current else ""
    calibration_source = _repository_path(release.calibration_path)
    calibration_link = (
        "`calibration data "
        f"<https://github.com/NVIDIA/garak/blob/main/{calibration_source}>`__"
    )

    bag = release.bag
    if bag is None:
        source_description = (
            f"See the archived {calibration_link}. No separate model-bag metadata "
            "or run configuration is stored for this calibration."
        )
    else:
        bag_source = _repository_path(bag.bag_path)
        config_source = _repository_path(bag.config_path)
        calibration_state = "current" if release.current else "archived"
        bag_state = "canonical" if bag.current else "frozen"
        source_description = (
            f"See the {calibration_state} {calibration_link}, "
            f"`{bag_state} model-bag data "
            f"<https://github.com/NVIDIA/garak/blob/main/{bag_source}>`__, and "
            f"`{bag_state} run configuration "
            f"<https://github.com/NVIDIA/garak/blob/main/{config_source}>`__."
        )
        if not release.current and release.release_id != bag.bag_id:
            source_description += (
                f" This calibration reuses model bag :ref:`{bag.bag_id} "
                f"<calibration-release-{bag.bag_id}>`."
            )

    lines = [
        f".. _calibration-release-{release.release_id}:",
        "",
        f".. rubric:: Calibration ``{release.release_id}``{current_label}",
        "",
        f"Generated on ``{release.generated_at[:10]}`` from "
        f"**{len(release.report_inputs)} report inputs**. {source_description}",
        "",
    ]
    show_bag_details = bag is not None and (
        release.current or (not bag.current and release.release_id == bag.bag_id)
    )
    if show_bag_details:
        assert bag is not None
        lines.extend(_render_model_table(bag.models))
        lines.extend(
            [
                "",
                ".. code-block:: yaml",
                f"   :caption: Model bag {bag.bag_id} run configuration",
                "",
            ]
        )
        lines.extend(f"   {line}" for line in bag.config.splitlines())
    else:
        lines.extend(_render_report_table(release.report_inputs))
    return "\n".join(lines)
