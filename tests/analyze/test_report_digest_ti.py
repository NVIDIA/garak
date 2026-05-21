# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import io
import json

import pytest

from garak import _config
import garak.analyze.report_digest as report_digest


def _base_records():
    return [
        {
            "entry_type": "start_run setup",
            "_config.version": "0.14.1.pre1",
            "plugins.probe_spec": "test.Test",
            "plugins.target_type": "test",
            "plugins.target_name": "Blank",
            "reporting.group_aggregation_function": "lower_quartile",
        },
        {
            "entry_type": "init",
            "garak_version": "0.14.1.pre1",
            "start_time": "2026-04-29T12:00:00",
            "run": "issue-1704-test-run",
        },
    ]


def _write_ti_report(tmp_path, intent_rows=None, technique_rows=None):
    _config.load_base_config()
    report_path = tmp_path / "ti.report.jsonl"
    records = _base_records()
    records.extend(intent_rows or [])
    records.extend(technique_rows or [])

    with open(report_path, "w", encoding="utf-8") as report_file:
        for record in records:
            report_file.write(json.dumps(record, ensure_ascii=False) + "\n")

    return report_path


def test_parse_report_collects_ti_eval_rows():
    records = _base_records()
    records.extend(
        [
            {
                "entry_type": "eval_intent",
                "probe": "intent.Test",
                "intent": "S009deep",
                "score": 0.5,
                "n_evaluations": 4,
                "aggregation": "lower_quartile",
            },
            {
                "entry_type": "eval_technique",
                "probe": "dan.Dan_6_0",
                "technique": "demon:Fictionalizing:Roleplaying:DAN_and_target_persona",
                "score": 0.0,
                "n_evaluations": 1,
                "aggregation": "lower_quartile",
            },
        ]
    )
    report = io.StringIO(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records)
    )

    (
        _init,
        _setup,
        _payloads,
        _evals,
        intent_evals,
        technique_evals,
        _plugin_cache,
    ) = report_digest._parse_report(report)

    assert intent_evals[0]["intent"] == "S009deep"
    assert technique_evals[0]["technique"].startswith("demon:")


def test_build_digest_includes_intent_summary(tmp_path):
    report_path = _write_ti_report(
        tmp_path,
        intent_rows=[
            {
                "entry_type": "eval_intent",
                "probe": "base.IntentProbe",
                "intent": "S009deep",
                "score": 0.75,
                "n_evaluations": 12,
                "detectors_used": ["always.Pass"],
                "aggregation": "lower_quartile",
            },
        ],
    )

    digest = report_digest.build_digest(str(report_path))

    assert digest["intent"]["S009deep"]["score"] == pytest.approx(0.75)
    assert digest["intent"]["S009deep"]["n_evaluations"] == 12
    assert digest["intent"]["S009deep"]["probes"] == ["base.IntentProbe"]
    assert digest["intent"]["S009deep"]["detectors_used"] == ["always.Pass"]
    assert digest["intent"]["S009deep"]["source_aggregations"] == ["lower_quartile"]


def test_build_digest_includes_empty_technique_bucket(tmp_path):
    report_path = _write_ti_report(
        tmp_path,
        technique_rows=[
            {
                "entry_type": "eval_technique",
                "probe": "test.Blank",
                "technique": None,
                "score": 1.0,
                "n_evaluations": 3,
                "detectors_used": ["always.Pass"],
                "aggregation": "lower_quartile",
            },
        ],
    )

    digest = report_digest.build_digest(str(report_path))

    assert "_untagged" in digest["technique"]
    assert digest["technique"]["_untagged"]["score"] == pytest.approx(1.0)
    assert digest["technique"]["_untagged"]["n_evaluations"] == 3


def test_digest_summary_allows_intent_and_multi_technique_coexistence(tmp_path):
    probe = "latentinjection.LatentInjectionFactSnippet"
    report_path = _write_ti_report(
        tmp_path,
        intent_rows=[
            {
                "entry_type": "eval_intent",
                "probe": probe,
                "intent": "S009deep",
                "score": 0.25,
                "n_evaluations": 8,
                "detectors_used": ["base.TriggerListDetector"],
                "aggregation": "lower_quartile",
            },
        ],
        technique_rows=[
            {
                "entry_type": "eval_technique",
                "probe": probe,
                "technique": "demon:Language:Prompt_injection:Stop_sequences",
                "score": 0.25,
                "n_evaluations": 8,
                "detectors_used": ["base.TriggerListDetector"],
                "aggregation": "lower_quartile",
            },
            {
                "entry_type": "eval_technique",
                "probe": probe,
                "technique": (
                    "demon:Language:Prompt_injection:" "Ignore_previous_instructions"
                ),
                "score": 0.25,
                "n_evaluations": 8,
                "detectors_used": ["base.TriggerListDetector"],
                "aggregation": "lower_quartile",
            },
        ],
    )

    digest = report_digest.build_digest(str(report_path))

    assert digest["intent"]["S009deep"]["probes"] == [probe]
    assert (
        digest["technique"]["demon:Language:Prompt_injection:Stop_sequences"][
            "n_evaluations"
        ]
        == 8
    )
    assert (
        digest["technique"][
            "demon:Language:Prompt_injection:Ignore_previous_instructions"
        ]["n_evaluations"]
        == 8
    )


def test_digest_ti_metric_semantics_use_landed_schema(tmp_path):
    technique = "demon:Language:Prompt_injection:Ignore_previous_instructions"
    report_path = _write_ti_report(
        tmp_path,
        technique_rows=[
            {
                "entry_type": "eval_technique",
                "probe": "probe.A",
                "technique": technique,
                "score": 0.8,
                "n_evaluations": 100,
                "detectors_used": ["detector.One"],
                "aggregation": "lower_quartile",
            },
            {
                "entry_type": "eval_technique",
                "probe": "probe.B",
                "technique": technique,
                "score": 0.4,
                "n_evaluations": 5,
                "detectors_used": ["detector.Two"],
                "aggregation": "mean",
            },
        ],
    )

    digest = report_digest.build_digest(str(report_path))

    bucket = digest["technique"][technique]
    assert bucket["score"] == pytest.approx(0.5)
    assert bucket["n_evaluations"] == 105
    assert bucket["probes"] == ["probe.A", "probe.B"]
    assert bucket["detectors_used"] == ["detector.One", "detector.Two"]
    assert bucket["source_aggregations"] == ["lower_quartile", "mean"]


def test_digest_rejects_missing_ti_value_key(tmp_path):
    report_path = _write_ti_report(
        tmp_path,
        technique_rows=[
            {
                "entry_type": "eval_technique",
                "probe": "test.Blank",
                "score": 1.0,
                "n_evaluations": 3,
                "detectors_used": ["always.Pass"],
            },
        ],
    )

    with pytest.raises(ValueError, match="eval_technique missing technique"):
        report_digest.build_digest(str(report_path))
