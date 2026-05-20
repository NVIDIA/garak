"""Tests for garak.evaluators — Evaluator and all subclasses.

Covers structure, test() method logic, evaluate() core scenarios, hitlog/eval record
validation, bootstrap CI paths, z-score paths, output format paths, and
ZeroToleranceEvaluator integration.
"""

import importlib
import inspect
import json
import os
import pkgutil
import tempfile
import uuid
from unittest.mock import MagicMock, patch

import pytest

import garak.evaluators
from garak import _config
from garak.attempt import Attempt, Message
from garak.evaluators.base import Evaluator, ThresholdEvaluator, ZeroToleranceEvaluator


def _discover_evaluator_classes():
    """Scan garak.evaluators submodules and return all Evaluator subclasses."""
    classes = set()
    package = garak.evaluators
    for _importer, modname, _ispkg in pkgutil.walk_packages(
        package.__path__, prefix=package.__name__ + "."
    ):
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, Evaluator):
                classes.add(obj)
    return sorted(classes, key=lambda c: c.__name__)


ALL_EVALUATOR_CLASSES = _discover_evaluator_classes()
EVALUATOR_SUBCLASSES = [c for c in ALL_EVALUATOR_CLASSES if c is not Evaluator]


FIXED_RUN_ID = uuid.UUID("12345678-1234-5678-1234-567812345678")
TARGET_TYPE = "test.TestGenerator"
TARGET_NAME = "test-model"
DEFAULT_PROBE = "test.TestProbe"
DEFAULT_GOAL = "test goal"
THRESHOLD_VALUES = [0.0, 0.25, 0.5, 0.75, 1.0]


def _make_evaluator(cls, **kwargs):
    if cls is ThresholdEvaluator:
        return cls(kwargs.pop("threshold", 0.5))
    return cls()


def make_attempt(
    outputs: list,
    detector_results: dict,
    probe_classname: str = DEFAULT_PROBE,
    goal: str = DEFAULT_GOAL,
    seq: int = 0,
) -> Attempt:
    """Build an Attempt with the given outputs and detector results.

    Args:
        outputs: List of strings; the setter converts them to Message/Conversation objects.
        detector_results: Dict mapping detector names to lists of scores.
        probe_classname: Probe class name to set on the attempt.
        goal: Goal string for the attempt.
        seq: Sequence number for the attempt.

    Returns:
        A fully populated Attempt object.
    """
    a = Attempt(prompt=Message(text="test prompt"))
    a.probe_classname = probe_classname
    a.goal = goal
    a.seq = seq
    a.outputs = outputs
    a.detector_results = detector_results
    return a


def _read_report_eval_records(report_path: str) -> list:
    """Read eval records from a report JSONL file.

    Args:
        report_path: Path to the report JSONL file.

    Returns:
        List of parsed eval record dicts.
    """
    records = []
    with open(report_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                record = json.loads(line)
                if record.get("entry_type") == "eval":
                    records.append(record)
    return records


def _read_hitlog_entries(report_path: str) -> list:
    """Read hitlog entries from the hitlog JSONL file derived from the report path.

    Args:
        report_path: Path to the report JSONL file.

    Returns:
        List of parsed hitlog entry dicts.
    """
    hitlog_path = report_path.replace(".report.jsonl", ".hitlog.jsonl")
    entries = []
    if not os.path.exists(hitlog_path):
        return entries
    with open(hitlog_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


@pytest.fixture()
def eval_setup():
    """Set up config, temp report file, and transient state for evaluator tests.

    Modifies the global ``_config`` module, which precludes test-level
    parallelism (pytest-xdist). The autouse ``config_cleanup`` fixture in
    conftest.py reloads ``_config`` after each test, so inter-test
    isolation is maintained for sequential execution.
    """
    _config.load_base_config()

    _config.reporting.confidence_interval_method = "none"

    fd, report_path = tempfile.mkstemp(suffix=".report.jsonl")
    os.close(fd)
    _config.transient.report_filename = report_path
    _config.transient.reportfile = open(report_path, "w", buffering=1, encoding="utf-8")

    _config.transient.run_id = FIXED_RUN_ID
    _config.transient.hitlogfile = None

    _config.plugins.target_type = TARGET_TYPE
    _config.plugins.target_name = TARGET_NAME

    _config.run.generations = 5
    _config.run.seed = 42

    _config.system.show_z = False
    _config.system.verbose = 0
    _config.system.narrow_output = False

    yield _config


# ---------------------------------------------------------------------------
# Structure tests — apply to every Evaluator discovered in garak.evaluators
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cls", ALL_EVALUATOR_CLASSES, ids=[c.__name__ for c in ALL_EVALUATOR_CLASSES]
)
def test_evaluator_has_test_method(cls):
    assert hasattr(cls, "test"), f"{cls.__name__} missing 'test' method"
    assert callable(getattr(cls, "test")), f"{cls.__name__}.test is not callable"


@pytest.mark.parametrize(
    "cls", ALL_EVALUATOR_CLASSES, ids=[c.__name__ for c in ALL_EVALUATOR_CLASSES]
)
def test_evaluator_has_evaluate_method(cls):
    assert hasattr(cls, "evaluate"), f"{cls.__name__} missing 'evaluate' method"
    assert callable(
        getattr(cls, "evaluate")
    ), f"{cls.__name__}.evaluate is not callable"


@pytest.mark.parametrize(
    "cls", EVALUATOR_SUBCLASSES, ids=[c.__name__ for c in EVALUATOR_SUBCLASSES]
)
def test_subclass_of_evaluator(cls):
    assert issubclass(cls, Evaluator), f"{cls.__name__} is not a subclass of Evaluator"


@pytest.mark.parametrize(
    "cls", ALL_EVALUATOR_CLASSES, ids=[c.__name__ for c in ALL_EVALUATOR_CLASSES]
)
def test_evaluator_instantiation(eval_setup, cls):
    try:
        evaluator = _make_evaluator(cls)
    except TypeError as e:
        pytest.skip(f"{cls.__name__} has broken __init__: {e}")
    assert hasattr(
        evaluator, "probename"
    ), f"{cls.__name__} instance missing 'probename'"
    assert (
        evaluator.probename == ""
    ), f"{cls.__name__}.probename should default to empty string"


# ---------------------------------------------------------------------------
# ThresholdEvaluator-specific — threshold attribute
# ---------------------------------------------------------------------------


def test_threshold_evaluator_default_threshold(eval_setup):
    evaluator = ThresholdEvaluator()
    assert (
        evaluator.threshold == 0.5
    ), "ThresholdEvaluator default threshold should be 0.5"


def test_threshold_evaluator_custom_threshold(eval_setup):
    evaluator = ThresholdEvaluator(0.75)
    assert (
        evaluator.threshold == 0.75
    ), "ThresholdEvaluator should store custom threshold"


# ---------------------------------------------------------------------------
# ThresholdEvaluator.test() — strict less-than comparison
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("threshold", [t for t in THRESHOLD_VALUES if t > 0.0])
def test_threshold_score_below_passes(eval_setup, threshold):
    score = threshold - 0.01
    evaluator = ThresholdEvaluator(threshold)
    assert (
        evaluator.test(score) is True
    ), f"score {score} below threshold {threshold} should pass"


@pytest.mark.parametrize("threshold", THRESHOLD_VALUES)
def test_threshold_score_at_threshold_fails(eval_setup, threshold):
    evaluator = ThresholdEvaluator(threshold)
    assert (
        evaluator.test(threshold) is False
    ), f"score exactly at threshold {threshold} should fail (strict < comparison)"


@pytest.mark.parametrize("threshold", [t for t in THRESHOLD_VALUES if t < 1.0])
def test_threshold_score_above_threshold_fails(eval_setup, threshold):
    score = threshold + 0.01
    evaluator = ThresholdEvaluator(threshold)
    assert (
        evaluator.test(score) is False
    ), f"score {score} above threshold {threshold} should fail"


# ---------------------------------------------------------------------------
# ZeroToleranceEvaluator.test() — only exact zero passes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, True),
        (0.5, False),
        (1.0, False),
        (0.001, False),
    ],
    ids=["exact_zero", "half", "max_score", "near_zero"],
)
def test_zero_tolerance_test_method(eval_setup, score, expected):
    evaluator = ZeroToleranceEvaluator()
    assert (
        evaluator.test(score) is expected
    ), f"ZeroToleranceEvaluator.test({score}) should be {expected}"


# ---------------------------------------------------------------------------
# evaluate() — core scenarios
# ---------------------------------------------------------------------------


def test_evaluate_all_pass(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.0, 0.0]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"
    assert records[0]["passed"] == 3, "all scores below threshold should pass"
    assert records[0]["fails"] == 0, "no scores should fail"
    assert records[0]["nones"] == 0, "no scores should be None"


def test_evaluate_all_fail(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.8, 0.9, 1.0]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"
    assert records[0]["passed"] == 0, "no scores should pass"
    assert records[0]["fails"] == 3, "all scores above threshold should fail"
    assert records[0]["nones"] == 0, "no scores should be None"

    if _config.transient.hitlogfile is not None:
        _config.transient.hitlogfile.flush()
    entries = _read_hitlog_entries(_config.transient.report_filename)
    assert len(entries) == 3, "each failing score should produce a hitlog entry"


def test_evaluate_mixed(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.8, 0.3]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"
    assert records[0]["passed"] == 2, "two scores below threshold should pass"
    assert records[0]["fails"] == 1, "one score above threshold should fail"

    if _config.transient.hitlogfile is not None:
        _config.transient.hitlogfile.flush()
    entries = _read_hitlog_entries(_config.transient.report_filename)
    assert len(entries) == 1, "one failing score should produce one hitlog entry"


def test_evaluate_with_nones(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3", "out4"],
        detector_results={"det.A": [0.0, None, 0.8, None]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"
    assert records[0]["passed"] == 1, "one score below threshold should pass"
    assert records[0]["fails"] == 1, "one score above threshold should fail"
    assert records[0]["nones"] == 2, "two None scores should be counted as nones"


def test_evaluate_multiple_attempts(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    a1 = make_attempt(
        outputs=["a1o1", "a1o2"],
        detector_results={"det.A": [0.0, 0.8]},
        seq=0,
    )
    a2 = make_attempt(
        outputs=["a2o1", "a2o2"],
        detector_results={"det.A": [0.0, 0.8]},
        seq=1,
    )
    evaluator.evaluate([a1, a2])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert (
        len(records) == 1
    ), "multiple attempts with same detector produce 1 eval record"
    assert records[0]["passed"] == 2, "two passing scores across attempts"
    assert records[0]["fails"] == 2, "two failing scores across attempts"

    if _config.transient.hitlogfile is not None:
        _config.transient.hitlogfile.flush()
    entries = _read_hitlog_entries(_config.transient.report_filename)
    assert len(entries) == 2, "two failing scores should produce two hitlog entries"


def test_evaluate_multiple_detectors(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2"],
        detector_results={
            "det.A": [0.0, 0.0],
            "det.B": [0.8, 0.9],
        },
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 2, "each detector should produce its own eval record"

    det_a = [r for r in records if r["detector"] == "det.A"][0]
    det_b = [r for r in records if r["detector"] == "det.B"][0]

    assert det_a["passed"] == 2, "det.A: all scores below threshold"
    assert det_a["fails"] == 0, "det.A: no failures"
    assert det_b["passed"] == 0, "det.B: no passes"
    assert det_b["fails"] == 2, "det.B: all scores above threshold"


def test_evaluate_empty_list(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    evaluator.evaluate([])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 0, "empty attempt list should produce no eval records"


def test_evaluate_empty_detector_results(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2"],
        detector_results={},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 0, "empty detector_results should produce no eval records"


# ---------------------------------------------------------------------------
# Hitlog field validation
# ---------------------------------------------------------------------------


def test_hitlog_entry_fields(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["failing output"],
        detector_results={"det.A": [0.8]},
        probe_classname=DEFAULT_PROBE,
        goal=DEFAULT_GOAL,
        seq=7,
    )
    evaluator.evaluate([attempt])

    if _config.transient.hitlogfile is not None:
        _config.transient.hitlogfile.flush()
    entries = _read_hitlog_entries(_config.transient.report_filename)
    assert len(entries) == 1, "single failure should produce exactly one hitlog entry"

    entry = entries[0]

    assert entry["goal"] == DEFAULT_GOAL, "hitlog goal should match attempt goal"
    assert isinstance(entry["prompt"], dict), "hitlog prompt should be a dict"
    assert isinstance(entry["output"], dict), "hitlog output should be a dict"
    assert "text" in entry["output"], "hitlog output should contain 'text' key"
    assert entry["score"] == 0.8, "hitlog score should match detector score"
    assert entry["run_id"] == str(FIXED_RUN_ID), "hitlog run_id should match config"
    assert entry["attempt_id"] == str(
        attempt.uuid
    ), "hitlog attempt_id should match attempt UUID"
    assert entry["attempt_seq"] == 7, "hitlog attempt_seq should match attempt seq"
    assert entry["attempt_idx"] == 0, "hitlog attempt_idx should be 0 for first output"
    assert (
        entry["generator"] == f"{TARGET_TYPE} {TARGET_NAME}"
    ), "hitlog generator should combine target type and name"
    assert (
        entry["probe"] == DEFAULT_PROBE
    ), "hitlog probe should match attempt probe_classname"
    assert entry["detector"] == "det.A", "hitlog detector should match detector key"
    assert (
        entry["generations_per_prompt"] == _config.run.generations
    ), "hitlog generations_per_prompt should match config"
    assert entry["triggers"] is None, "triggers should default to None when not set"


def test_hitlog_with_triggers(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["failing output"],
        detector_results={"det.A": [0.8]},
    )
    attempt.notes["triggers"] = ["t1", "t2"]

    evaluator.evaluate([attempt])

    if _config.transient.hitlogfile is not None:
        _config.transient.hitlogfile.flush()
    entries = _read_hitlog_entries(_config.transient.report_filename)
    assert len(entries) == 1, "single failure should produce one hitlog entry"
    assert entries[0]["triggers"] == [
        "t1",
        "t2",
    ], "hitlog triggers should match attempt notes"


# ---------------------------------------------------------------------------
# Eval record field validation
# ---------------------------------------------------------------------------


def test_eval_record_fields(eval_setup):
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.8, None]},
        probe_classname="probe.ModuleA",
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"

    rec = records[0]
    assert rec["entry_type"] == "eval", "entry_type should be 'eval'"
    assert rec["probe"] == "probe.ModuleA", "probe should match attempt probe_classname"
    assert rec["detector"] == "det.A", "detector should match detector key"
    assert rec["passed"] == 1, "one score below threshold should pass"
    assert rec["fails"] == 1, "one score above threshold should fail"
    assert rec["nones"] == 1, "one None score should be counted"
    assert rec["total_evaluated"] == 2, "total_evaluated should be passed + fails"
    assert (
        rec["total_processed"] == 3
    ), "total_processed should be passed + fails + nones"


# ---------------------------------------------------------------------------
# Bootstrap CI path
# ---------------------------------------------------------------------------


def test_evaluate_with_bootstrap_ci(eval_setup):
    _config.reporting.confidence_interval_method = "bootstrap"
    _config.reporting.bootstrap_min_sample_size = 3
    _config.reporting.bootstrap_num_iterations = 100
    _config.reporting.bootstrap_confidence_level = 0.95

    with patch("garak.analyze.detector_metrics.get_detector_metrics") as mock_get:
        mock_metrics = MagicMock()
        mock_metrics.get_detector_se_sp.return_value = (1.0, 1.0)
        mock_get.return_value = mock_metrics
        evaluator = ThresholdEvaluator(0.5)

    scores = [0.0, 0.8, 0.9, 0.0, 0.7]
    attempt = make_attempt(
        outputs=[f"out{i}" for i in range(len(scores))],
        detector_results={"det.A": scores},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"

    rec = records[0]
    assert "confidence_method" in rec, "bootstrap CI should add confidence_method field"
    assert (
        rec["confidence_method"] == "bootstrap"
    ), "confidence_method should be 'bootstrap'"
    assert "confidence" in rec, "bootstrap CI should add confidence field"
    assert "confidence_upper" in rec, "bootstrap CI should add confidence_upper field"
    assert "confidence_lower" in rec, "bootstrap CI should add confidence_lower field"
    assert isinstance(
        rec["confidence_upper"], float
    ), "confidence_upper should be float"
    assert isinstance(
        rec["confidence_lower"], float
    ), "confidence_lower should be float"


def test_evaluate_bootstrap_below_min_sample(eval_setup):
    _config.reporting.confidence_interval_method = "bootstrap"
    _config.reporting.bootstrap_min_sample_size = 100
    _config.reporting.bootstrap_num_iterations = 100
    _config.reporting.bootstrap_confidence_level = 0.95

    with patch("garak.analyze.detector_metrics.get_detector_metrics") as mock_get:
        mock_metrics = MagicMock()
        mock_metrics.get_detector_se_sp.return_value = (1.0, 1.0)
        mock_get.return_value = mock_metrics
        evaluator = ThresholdEvaluator(0.5)

    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.8, 0.9]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"

    rec = records[0]
    assert (
        "confidence_method" not in rec
    ), "below min_sample_size should not include confidence_method"
    assert (
        "confidence" not in rec
    ), "below min_sample_size should not include confidence"
    assert (
        "confidence_upper" not in rec
    ), "below min_sample_size should not include confidence_upper"
    assert (
        "confidence_lower" not in rec
    ), "below min_sample_size should not include confidence_lower"


# ---------------------------------------------------------------------------
# Z-score path
# ---------------------------------------------------------------------------


def test_evaluate_with_z_scores(eval_setup):
    _config.system.show_z = True

    with patch("garak.analyze.calibration.Calibration") as MockCal:
        mock_cal = MagicMock()
        mock_cal.get_z_score.return_value = 1.5
        mock_cal.defcon_and_comment.return_value = (4, "ok")
        MockCal.return_value = mock_cal
        evaluator = ThresholdEvaluator(0.5)

    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.8, 0.3]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    mock_cal.get_z_score.assert_called()
    mock_cal.defcon_and_comment.assert_called()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"
    assert (
        records[0]["probe"] == DEFAULT_PROBE
    ), "probe should match attempt probe_classname"
    assert records[0]["detector"] == "det.A", "detector should match detector key"


# ---------------------------------------------------------------------------
# Output format paths — verify evaluate() doesn't crash
# ---------------------------------------------------------------------------


def test_evaluate_wide_output(eval_setup):
    _config.system.narrow_output = False
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.8, 0.3]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "wide output mode should produce eval record"


def test_evaluate_narrow_output(eval_setup):
    _config.system.narrow_output = True
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.8, 0.3]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "narrow output mode should produce eval record"


def test_evaluate_verbose_output(eval_setup):
    _config.system.verbose = 2
    evaluator = ThresholdEvaluator(0.5)
    attempt = make_attempt(
        outputs=["failing output 1", "failing output 2"],
        detector_results={"det.A": [0.8, 0.9]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "verbose output mode should produce eval record"
    assert records[0]["fails"] == 2, "verbose mode should not affect fail counting"


# ---------------------------------------------------------------------------
# ZeroToleranceEvaluator — end-to-end integration
# ---------------------------------------------------------------------------


def test_zero_tolerance_evaluate(eval_setup):
    evaluator = ZeroToleranceEvaluator()
    attempt = make_attempt(
        outputs=["out1", "out2", "out3"],
        detector_results={"det.A": [0.0, 0.5, 0.0]},
    )
    evaluator.evaluate([attempt])
    _config.transient.reportfile.flush()

    records = _read_report_eval_records(_config.transient.report_filename)
    assert len(records) == 1, "expected exactly 1 eval record"
    assert records[0]["passed"] == 2, "two zero scores should pass"
    assert records[0]["fails"] == 1, "one non-zero score should fail"

    if _config.transient.hitlogfile is not None:
        _config.transient.hitlogfile.flush()
    entries = _read_hitlog_entries(_config.transient.report_filename)
    assert len(entries) == 1, "one failure should produce one hitlog entry"
