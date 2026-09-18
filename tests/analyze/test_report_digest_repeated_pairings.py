# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Digests of aggregated reports must pool a probe/detector pairing written by more than one run.

``garak.analyze.aggregate_reports`` documents itself as the way to assemble "a report
that's been run one probe at a time", and it copies each source report's ``eval`` and
``probe_summary`` rows verbatim. When the same pairing appears in two source runs the
digest used to report one of them and silently drop the other.
"""

import json

import pytest

from garak import _config
import garak.analyze.report_digest

_ASSET = "tests/_assets/analyze/test.report.jsonl"


def _pool(records):
    return garak.analyze.report_digest._pool_repeated_pairings(records)


def _eval(
    passed, total_evaluated, detector="always.Pass", probe="test.Test", intents=None
):
    record = {
        "entry_type": "eval",
        "probe": probe,
        "detector": detector,
        "passed": passed,
        "fails": total_evaluated - passed,
        "nones": 0,
        "total_evaluated": total_evaluated,
        "total_processed": total_evaluated,
    }
    if intents is not None:
        record["intents"] = intents
    return record


def _probe_summary(passed, total_evaluated, detector="always.Pass"):
    return {
        "entry_type": "probe_summary",
        "probe": "test.Test",
        "inference_counts": {"total_evaluated": total_evaluated, "nones": 0},
        "detection_counts": {
            "detectors": [detector],
            "passed": passed,
            "fails": total_evaluated - passed,
            "nones": 0,
        },
    }


def _digest_for(records, tmp_path):
    """setup + init lines come from a real report; the rows after them are the pairing under test."""
    with open(_ASSET, encoding="utf-8") as source:
        header = [source.readline(), source.readline()]

    report_path = tmp_path / "aggregated.report.jsonl"
    with open(report_path, "w", encoding="utf-8") as out:
        out.writelines(header)
        for record in records:
            out.write(json.dumps(record, ensure_ascii=False) + "\n")

    _config.load_base_config()
    _config.reporting.taxonomy = None
    return garak.analyze.report_digest.build_digest(str(report_path))


def test_repeated_pairing_counts_add_up(tmp_path):
    digest = _digest_for(
        [_eval(8, 8), _eval(16, 16), _probe_summary(8, 8), _probe_summary(16, 16)],
        tmp_path,
    )

    entry = digest["eval"]["test"]["test.Test"]["always.Pass"]

    assert entry["total_evaluated"] == 24, "evaluations from both runs are reported"
    assert entry["passed"] == 24, "passes from both runs are reported"


def test_clean_chunk_cannot_mask_a_failing_one(tmp_path):
    """Row shapes are what aggregation writes; the 0/10 + 10/10 split misreports either
    way round if one chunk wins, so the pooled score is the only honest answer."""
    digest = _digest_for(
        [_eval(0, 10), _eval(10, 10), _probe_summary(0, 10), _probe_summary(10, 10)],
        tmp_path,
    )

    entry = digest["eval"]["test"]["test.Test"]["always.Pass"]

    assert entry["total_evaluated"] == 20, "denominator pools both runs"
    assert entry["passed"] == 10, "numerator pools both runs"
    assert entry["absolute_score"] == pytest.approx(
        0.5
    ), "score is computed over pooled counts, not over whichever chunk won"
    assert entry["absolute_defcon"] < 5, "a half-failing pairing is not minimal risk"


def test_probe_and_detector_counts_agree(tmp_path):
    digest = _digest_for(
        [_eval(8, 8), _eval(16, 16), _probe_summary(8, 8), _probe_summary(16, 16)],
        tmp_path,
    )

    probe = digest["eval"]["test"]["test.Test"]["_summary"]
    entry = digest["eval"]["test"]["test.Test"]["always.Pass"]

    assert probe["probe_counts"]["inference_counts"]["total_evaluated"] == 24
    assert (
        probe["probe_counts"]["detection_counts"]["passed"] == entry["passed"] == 24
    ), "the probe summary and its detector row must describe the same pooled total"
    assert probe["probe_counts"]["detection_counts"]["detectors"] == [
        "always.Pass"
    ], "pooling must not list a detector twice"


def test_single_chunk_pairing_is_left_alone():
    (pooled,) = _pool([_eval(6, 6)])

    assert (
        pooled["total_evaluated"] == 6 and pooled["passed"] == 6
    ), "one row is its own pool"


def test_unrepeated_pairing_keeps_its_interval():
    record = dict(
        _eval(6, 6), confidence="0.95", confidence_lower=0.8, confidence_upper=1.0
    )

    (pooled,) = _pool([record])

    assert (
        pooled["confidence_lower"] == 0.8
    ), "a pairing run once keeps its own interval"


def test_pooled_pairing_keeps_no_single_chunk_interval():
    records = [
        dict(
            _eval(4, 4), confidence="0.95", confidence_lower=0.8, confidence_upper=1.0
        ),
        dict(
            _eval(6, 6), confidence="0.95", confidence_lower=0.9, confidence_upper=1.0
        ),
    ]

    pooled = _pool(records)

    assert len(pooled) == 1
    assert pooled[0]["total_evaluated"] == 10 and pooled[0]["passed"] == 10
    assert (
        "confidence_lower" not in pooled[0] and "confidence_upper" not in pooled[0]
    ), "an interval describes one sample set, so it may not describe a pooled total"


def test_distinct_pairings_keep_their_own_rows():
    records = [
        _eval(1, 2),
        _eval(3, 4, detector="always.Fail"),
        _eval(5, 6, probe="test.Other"),
    ]

    pooled = _pool(records)

    assert len(pooled) == 3, "only repeated probe/detector pairs are pooled"
    assert [r["total_evaluated"] for r in pooled] == [2, 4, 6]


def test_pooling_does_not_mutate_the_rows_it_was_given():
    records = [
        _eval(1, 1, intents={"S003": {"passed": 1, "total_evaluated": 1, "nones": 0}}),
        _eval(2, 2, intents={"S003": {"passed": 2, "total_evaluated": 2, "nones": 0}}),
    ]
    untouched = json.loads(json.dumps(records))

    _pool(records)

    assert (
        records == untouched
    ), "pooling works on copies, so the report rows stay as parsed"


def test_intents_are_summed_not_replaced():
    records = [
        _eval(3, 6, intents={"S003": {"passed": 3, "total_evaluated": 6, "nones": 0}}),
        _eval(2, 4, intents={"S003": {"passed": 2, "total_evaluated": 4, "nones": 0}}),
    ]

    pooled = _pool(records)

    assert pooled[0]["intents"]["S003"] == {
        "passed": 5,
        "total_evaluated": 10,
        "nones": 0,
    }, "technique counts pool once, not twice"


def test_eval_without_intents_stays_without_them():
    pooled = _pool([_eval(1, 1), _eval(2, 2)])

    assert (
        "intents" not in pooled[0]
    ), "the technique matrix skips rows with no intents; pooling must not invent one"
