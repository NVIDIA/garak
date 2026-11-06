"""Keep rebuilt digest scores and labels tied to the intended configuration."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from garak import _config
from garak.analyze.report_digest import build_digest


def _report_with_scores(tmp_path, aggregation_function):
    source = Path(__file__).parents[1] / "_assets" / "analyze" / "test.report.jsonl"
    with source.open(encoding="utf-8") as report:
        setup = json.loads(next(report))
        init = next(report)
    if aggregation_function is None:
        setup.pop("reporting.group_aggregation_function", None)
    else:
        setup["reporting.group_aggregation_function"] = aggregation_function

    report_path = tmp_path / "different_aggregation.report.jsonl"
    evaluations = [
        {
            "entry_type": "eval",
            "probe": "test.Test",
            "detector": detector,
            "passed": passed,
            "total_evaluated": 1,
        }
        for detector, passed in (("always.Pass", 1), ("always.Fail", 0))
    ]
    report_path.write_text(
        json.dumps(setup)
        + "\n"
        + init
        + "".join(json.dumps(entry) + "\n" for entry in evaluations),
        encoding="utf-8",
    )
    return report_path


def test_rebuilt_digest_uses_active_aggregation(tmp_path, monkeypatch, caplog):
    _config.load_base_config()
    monkeypatch.setattr(
        _config.reporting, "group_aggregation_function", "lower_quartile"
    )
    report_path = _report_with_scores(tmp_path, "mean")

    digest = build_digest(str(report_path))

    summary = digest["eval"]["test"]["_summary"]
    assert summary["score"] == 0.25, "the active method should determine the score"
    assert (
        summary["group_aggregation_function"] == "lower_quartile"
    ), "group metadata should name the active aggregation"
    assert (
        digest["meta"]["group_aggregation_function"] == "lower_quartile"
    ), "report metadata should name the active aggregation"
    assert (
        digest["meta"]["setup"]["reporting.group_aggregation_function"]
        == "lower_quartile"
    ), "digest setup should agree with the score"
    assert "Report used mean aggregation" in caplog.text


def test_explicit_digest_config_overrides_saved_aggregation(tmp_path, monkeypatch):
    _config.load_base_config()
    monkeypatch.setattr(
        _config.reporting, "group_aggregation_function", "lower_quartile"
    )
    report_path = _report_with_scores(tmp_path, "minimum")

    config = SimpleNamespace(
        reporting=SimpleNamespace(group_aggregation_function="mean", taxonomy=None)
    )
    digest = build_digest(str(report_path), config=config)

    summary = digest["eval"]["test"]["_summary"]
    assert summary["score"] == 0.5, "the explicit mean should determine the group score"
    assert (
        summary["group_aggregation_function"] == "mean"
    ), "group metadata should name the explicit aggregation"
    assert (
        digest["meta"]["group_aggregation_function"] == "mean"
    ), "report metadata should name the explicit aggregation"
    assert (
        digest["meta"]["setup"]["reporting.group_aggregation_function"] == "mean"
    ), "digest setup should name the explicit aggregation"


def test_rebuilt_digest_uses_current_aggregation_for_older_reports(
    tmp_path, monkeypatch
):
    _config.load_base_config()
    monkeypatch.setattr(
        _config.reporting, "group_aggregation_function", "lower_quartile"
    )
    report_path = _report_with_scores(tmp_path, None)

    digest = build_digest(str(report_path))

    summary = digest["eval"]["test"]["_summary"]
    assert summary["score"] == 0.25, "older reports should use the current method"
    assert (
        summary["group_aggregation_function"] == "lower_quartile"
    ), "group metadata should name the current method"


def _report_records(report_path):
    return [
        json.loads(line)
        for line in report_path.read_text(encoding="utf-8").splitlines()
    ]


def _assert_aggregation_consistent(report_path, method, score):
    records = _report_records(report_path)
    digests = [record for record in records if record["entry_type"] == "digest"]
    assert len(digests) == 1, "the output should contain one current digest"
    setup = next(
        record for record in records if record["entry_type"] == "start_run setup"
    )
    digest = digests[0]
    assert setup["reporting.group_aggregation_function"] == method
    assert digest["meta"]["setup"]["reporting.group_aggregation_function"] == method
    assert digest["meta"]["group_aggregation_function"] == method
    summary = digest["eval"]["test"]["_summary"]
    assert summary["group_aggregation_function"] == method
    assert summary["score"] == score


def test_aggregate_cli_uses_active_or_requested_aggregation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    source = _report_with_scores(tmp_path, "mean")
    default_output = tmp_path / "default.report.jsonl"
    command = [
        sys.executable,
        "-m",
        "garak.analyze.aggregate_reports",
        "-o",
        str(default_output),
        str(source),
    ]

    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert "Report used mean aggregation" in result.stderr
    _assert_aggregation_consistent(default_output, "lower_quartile", 0.25)

    requested_output = tmp_path / "requested.report.jsonl"
    command[command.index(str(default_output))] = str(requested_output)
    command[3:3] = ["--group_aggregation_function", "mean"]
    subprocess.run(command, capture_output=True, text=True, check=True)
    _assert_aggregation_consistent(requested_output, "mean", 0.5)


def test_aggregate_cli_keeps_source_taxonomy(tmp_path):
    source = _report_with_scores(tmp_path, "mean")
    records = _report_records(source)
    records[0]["reporting.taxonomy"] = "avid-effect"
    source.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    output_path = tmp_path / "taxonomy.report.jsonl"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.aggregate_reports",
            "-o",
            str(output_path),
            "--group_aggregation_function",
            "mean",
            str(source),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    output_records = _report_records(output_path)
    digest = output_records[-1]
    assert output_records[0]["reporting.taxonomy"] == "avid-effect"
    assert digest["meta"]["setup"]["reporting.taxonomy"] == "avid-effect"


def test_report_digest_cli_replaces_stale_digest_and_setup(tmp_path):
    report_path = _report_with_scores(tmp_path, "mean")
    with report_path.open("a", encoding="utf-8") as report:
        report.write(
            json.dumps({"entry_type": "digest", "meta": {}, "eval": {}}) + "\n"
        )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.report_digest",
            "-r",
            str(report_path),
            "-o",
            str(tmp_path / "report.html"),
            "-w",
            "--group_aggregation_function",
            "minimum",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    _assert_aggregation_consistent(report_path, "minimum", 0.0)


def test_rebuild_cis_cli_records_requested_aggregation(tmp_path, monkeypatch):
    source = (
        Path(__file__).parents[1] / "_assets" / "analyze" / "test_with_ci.report.jsonl"
    )
    records = [
        record for record in _report_records(source) if record["entry_type"] != "digest"
    ]
    setup = next(
        record for record in records if record["entry_type"] == "start_run setup"
    )
    setup["reporting.group_aggregation_function"] = "minimum"
    extra_eval = {
        "entry_type": "eval",
        "probe": "test.Test",
        "detector": "always.Fail",
        "passed": 13,
        "total_evaluated": 50,
        "fails": 37,
        "total_processed": 50,
        "nones": 0,
    }
    records.append(extra_eval)
    report_path = tmp_path / "source.report.jsonl"
    report_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    _config.load_base_config()
    monkeypatch.setattr(_config.reporting, "group_aggregation_function", "minimum")
    with report_path.open("a", encoding="utf-8") as report:
        report.write(json.dumps(build_digest(str(report_path))) + "\n")
    output_path = tmp_path / "rebuilt.report.jsonl"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.rebuild_cis",
            "-r",
            str(report_path),
            "-o",
            str(output_path),
            "--group_aggregation_function",
            "mean",
            "--bootstrap_num_iterations",
            "10",
            "--bootstrap_min_sample_size",
            "1",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Report used minimum aggregation" in result.stderr
    assert output_path.exists(), (result.stdout or "") + (result.stderr or "")
    _assert_aggregation_consistent(output_path, "mean", 0.5)


def test_rebuild_cis_cli_updates_aggregation_without_new_intervals(
    tmp_path, monkeypatch
):
    report_path = _report_with_scores(tmp_path, "minimum")
    _config.load_base_config()
    monkeypatch.setattr(_config.reporting, "group_aggregation_function", "minimum")
    with report_path.open("a", encoding="utf-8") as report:
        report.write(json.dumps(build_digest(str(report_path))) + "\n")
    output_path = tmp_path / "rebuilt.report.jsonl"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.rebuild_cis",
            "-r",
            str(report_path),
            "-o",
            str(output_path),
            "--group_aggregation_function",
            "mean",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    _assert_aggregation_consistent(output_path, "mean", 0.5)
    assert all(
        "confidence_lower" not in record
        for record in _report_records(output_path)
        if record["entry_type"] == "eval"
    ), "the aggregation should rebuild even when no intervals can be calculated"
