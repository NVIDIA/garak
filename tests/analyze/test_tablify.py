# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import csv
import io
import json

from garak.analyze.tablify import tablify


def _write_report(report_path, records) -> None:
    with open(report_path, "w", encoding="utf-8") as report_file:
        for record in records:
            report_file.write(json.dumps(record) + "\n")


def test_tablify_writes_deduplicated_csv(tmp_path, capsys) -> None:
    report_path = tmp_path / "input.report.jsonl"
    output_path = tmp_path / "output.csv"
    _write_report(
        report_path,
        [
            {
                "entry_type": "attempt",
                "status": 2,
                "probe_classname": "probe.one",
                "prompt": "hello",
                "outputs": ["same output", "same output"],
                "detector_results": {"detector.alpha": [0.1, 0.1]},
            },
            {
                "entry_type": "attempt",
                "status": 2,
                "probe_classname": "probe.one",
                "prompt": "hello",
                "outputs": ["same output", "same output"],
                "detector_results": {"detector.alpha": [0.1, 0.1]},
            },
            {
                "entry_type": "attempt",
                "status": 2,
                "probe_classname": "probe.one",
                "prompt": "hello",
                "outputs": ["different output"],
                "detector_results": {"detector.beta": [0.2]},
            },
            {
                "entry_type": "attempt",
                "status": 1,
                "probe_classname": "probe.ignored",
                "prompt": "skip me", # attempt status 1 are skipped
                "outputs": ["ignored"],
                "detector_results": {"detector.alpha": [0.9]},
            },
        ],
    )

    tablify(str(report_path), str(output_path))

    with open(output_path, "r", encoding="utf-8", newline="") as output_file:
        rows = list(csv.DictReader(output_file))

    assert {tuple(sorted(row.items())) for row in rows} == {
        (
            ("detector", "detector.alpha"),
            ("output", "same output"),
            ("probe", "probe.one"),
            ("prompt", "hello"),
            ("score", "0.1"),
        ),
        (
            ("detector", "detector.beta"),
            ("output", "different output"),
            ("probe", "probe.one"),
            ("prompt", "hello"),
            ("score", "0.2"),
        ),
    }

    captured = capsys.readouterr()
    assert (
        captured.out
        == f"Evaluated 3 entries. Wrote 2 lines to {output_path}.\n"
    )


def test_tablify_writes_csv_to_stdout_without_none_outputs(tmp_path, capsys) -> None:
    report_path = tmp_path / "input.report.jsonl"
    _write_report(
        report_path,
        [
            {
                "entry_type": "attempt",
                "status": 2,
                "probe_classname": "probe.one",
                "prompt": "hello",
                "outputs": [None, "keep me"],
                "detector_results": {"detector.alpha": [0.9]},
            }
        ],
    )

    tablify(str(report_path), None)

    captured = capsys.readouterr()
    rows = list(csv.DictReader(io.StringIO(captured.out)))
    assert rows == [
        {
            "probe": "probe.one",
            "prompt": "hello",
            "output": "keep me",
            "detector": "detector.alpha",
            "score": "0.9",
        }
    ]
