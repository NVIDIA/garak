# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import sys
import tempfile

from garak import _config
import garak.analyze.report_digest

TEMP_PREFIX = "_garak_internal_test_temp"


def _write_ti_aggregate_report(tmp_path, filename, probe, intent, technique):
    report_path = tmp_path / filename
    records = [
        {
            "entry_type": "start_run setup",
            "_config.version": "0.14.1.pre1",
            "plugins.target_type": "test",
            "plugins.target_name": "Blank",
            "plugins.probe_spec": probe,
            "reporting.group_aggregation_function": "lower_quartile",
        },
        {
            "entry_type": "init",
            "garak_version": "0.14.1.pre1",
            "start_time": "2026-04-29T12:00:00",
            "run": filename,
        },
        {
            "entry_type": "eval_intent",
            "probe": probe,
            "intent": intent,
            "score": 0.75,
            "n_evaluations": 12,
            "detectors_used": ["always.Pass"],
        },
        {
            "entry_type": "eval_technique",
            "probe": probe,
            "technique": technique,
            "score": 0.75,
            "n_evaluations": 12,
            "detectors_used": ["always.Pass"],
        },
    ]

    with open(report_path, "w", encoding="utf-8") as report_file:
        for record in records:
            report_file.write(json.dumps(record, ensure_ascii=False) + "\n")

    return report_path


def test_aggregate_executes() -> None:

    _config.load_base_config()

    aggfile = tempfile.NamedTemporaryFile(delete=False, encoding="utf-8", mode="w")
    aggfile_name = aggfile.name

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.aggregate_reports",
            "-o",
            aggfile_name,
            "tests/_assets/analyze/test.report.jsonl",
            "tests/_assets/analyze/quack.report.jsonl",
        ],
        check=True,
    )
    assert result.returncode == 0, "aggregate_reports failed"

    digest = garak.analyze.report_digest._get_report_digest(aggfile_name)
    assert digest != False, "digest record missing from aggregated jsonl"
    assert "intent" in digest
    assert "technique" in digest

    agg_digest_eval_keys = set(digest["eval"].keys())
    assert agg_digest_eval_keys == {
        "test",
        "lmrc",
    }, f"aggregated digest eval keys not as expected (got {agg_digest_eval_keys})"

    with open(aggfile_name, encoding="utf-8") as agg_jsonl_output_file:
        agg_lines = agg_jsonl_output_file.readlines()

    with open(
        "tests/_assets/analyze/agg.report.jsonl", encoding="utf-8"
    ) as ref_jsonl_output_file:
        ref_lines = ref_jsonl_output_file.readlines()

    assert len(agg_lines) == len(
        ref_lines
    ), f"unexpected aggregate line count, expected {len(ref_lines)} got {len(agg_lines)}"

    # skip calibration
    setup_agg = json.loads(agg_lines.pop(0))
    setup_ref = json.loads(ref_lines.pop(0))

    assert setup_agg["plugins.probe_spec"] == setup_ref["plugins.probe_spec"]

    for i in range(len(agg_lines)):
        agg_rec = json.loads(agg_lines[i])
        ref_rec = json.loads(ref_lines[i])

        if i == 0:  # init line
            assert agg_rec["orig_uuid"] == ref_rec["orig_uuid"]
            assert agg_rec["orig_start_time"] == ref_rec["orig_start_time"]
            continue

        if "uuid" in ref_rec:
            del (
                ref_rec["uuid"],
                agg_rec["uuid"],
            )  # key not found in agg rec means agg rec is out of sync (test fail)

        if ref_rec["entry_type"] == "digest":
            for key in ["intent", "technique"]:
                ref_rec.pop(key, None)
                agg_rec.pop(key, None)
            for key in [
                "run_uuid",
                "start_time",
                "reportfile",
                "report_digest_time",
                "calibration",
                "plugin_cache_source",
            ]:
                ref_rec["meta"].pop(key, None)
                agg_rec["meta"].pop(key, None)

        assert (
            agg_rec == ref_rec
        ), f"aggregated data mismatch in line {i+1}, expected\n{ref_rec}\ngot\n{agg_rec}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.report_digest",
            "-r",
            aggfile_name,
        ],
        check=True,
    )
    assert result.returncode == 0, "report html generation failed over aggregate"


def test_aggregate_preserves_mixed_eval_ci_format() -> None:
    """Aggregating a report without CI and one with CI preserves both eval formats."""
    _config.load_base_config()

    aggfile = tempfile.NamedTemporaryFile(delete=False, encoding="utf-8", mode="w")
    aggfile_name = aggfile.name
    aggfile.close()

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.aggregate_reports",
            "-o",
            aggfile_name,
            "tests/_assets/analyze/test.report.jsonl",
            "tests/_assets/analyze/test_with_ci.report.jsonl",
        ],
        check=True,
        capture_output=True,
    )
    assert result.returncode == 0, f"aggregate_reports failed: {result.stderr!r}"

    eval_entries = []
    with open(aggfile_name, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("entry_type") == "eval":
                eval_entries.append(rec)

    assert (
        len(eval_entries) >= 2
    ), "expected at least two eval entries (one without CI, one with CI)"
    has_no_ci = any("confidence_lower" not in e for e in eval_entries)
    has_ci = any(
        e.get("confidence_method") == "bootstrap"
        and "confidence_lower" in e
        and "confidence_upper" in e
        for e in eval_entries
    )
    assert (
        has_no_ci
    ), "aggregated output should contain at least one eval without CI fields"
    assert (
        has_ci
    ), "aggregated output should contain at least one eval with CI fields preserved"


def test_aggregate_preserves_ti_eval_rows(tmp_path) -> None:
    """Aggregate reports should preserve T&I eval rows without synthetic UUIDs."""
    _config.load_base_config()
    output_path = tmp_path / "aggregate_ti.report.jsonl"
    technique = "demon:Language:Prompt_injection:Ignore_previous_instructions"
    report_a = _write_ti_aggregate_report(
        tmp_path,
        "ti_a.report.jsonl",
        "probe.A",
        "S009deep",
        technique,
    )
    report_b = _write_ti_aggregate_report(
        tmp_path,
        "ti_b.report.jsonl",
        "probe.B",
        "S009deep",
        technique,
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.aggregate_reports",
            "-o",
            str(output_path),
            str(report_a),
            str(report_b),
        ],
        check=True,
        capture_output=True,
    )

    assert result.returncode == 0, f"aggregate_reports failed: {result.stderr!r}"

    rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    intent_rows = [row for row in rows if row["entry_type"] == "eval_intent"]
    technique_rows = [row for row in rows if row["entry_type"] == "eval_technique"]
    ti_rows = intent_rows + technique_rows

    assert len(intent_rows) == 2
    assert len(technique_rows) == 2
    assert all("uuid" not in row for row in ti_rows)

    digest = garak.analyze.report_digest._get_report_digest(str(output_path))
    assert digest["intent"]["S009deep"]["n_evaluations"] == 24
    assert digest["technique"][technique]["n_evaluations"] == 24


def test_digest_handles_mixed_eval_ci_format(tmp_path) -> None:
    """Digest builds successfully when report has both eval entries with and without CI."""
    _config.load_base_config()

    report_path = tmp_path / "mixed_ci.report.jsonl"
    with open(
        "tests/_assets/analyze/test.report.jsonl",
        encoding="utf-8",
    ) as f:
        setup_line = f.readline()
        init_line = f.readline()

    eval_no_ci = {
        "entry_type": "eval",
        "probe": "test.Test",
        "detector": "always.Pass",
        "passed": 5,
        "total_evaluated": 10,
        "fails": 0,
        "nones": 0,
        "total_processed": 10,
    }
    eval_with_ci = {
        "entry_type": "eval",
        "probe": "lmrc.QuackMedicine",
        "detector": "lmrc.QuackMedicine",
        "passed": 1,
        "total_evaluated": 1,
        "fails": 0,
        "nones": 0,
        "total_processed": 1,
        "confidence_method": "bootstrap",
        "confidence": "0.95",
        "confidence_lower": 0.0,
        "confidence_upper": 1.0,
    }

    with open(report_path, "w", encoding="utf-8") as out:
        out.write(setup_line)
        out.write(init_line)
        out.write(json.dumps(eval_no_ci, ensure_ascii=False) + "\n")
        out.write(json.dumps(eval_with_ci, ensure_ascii=False) + "\n")

    digest = garak.analyze.report_digest.build_digest(str(report_path))

    assert digest["entry_type"] == "digest"
    assert "eval" in digest
    assert "test" in digest["eval"]
    assert "lmrc" in digest["eval"]

    test_detectors = digest["eval"]["test"]["test.Test"]
    lmrc_detectors = digest["eval"]["lmrc"]["lmrc.QuackMedicine"]
    always_pass = test_detectors.get("always.Pass", {})
    quack = lmrc_detectors.get("lmrc.QuackMedicine", {})

    assert "absolute_score" in always_pass
    assert "absolute_score" in quack
    assert (
        "absolute_confidence_lower" not in always_pass
        or always_pass.get("absolute_confidence_lower") is None
    )
    assert "absolute_confidence_lower" in quack
    assert "absolute_confidence_upper" in quack
