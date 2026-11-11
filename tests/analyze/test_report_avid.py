# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import shutil

import pytest

from garak.analyze.report_avid import convert_to_avid


@pytest.fixture
def exported_avid(tmp_path, request):
    """Export the shared sample report through the module-level entry point."""
    report = tmp_path / "report_test.report.jsonl"
    shutil.copy("tests/_assets/report/report_test.report.jsonl", report)

    avid_path = convert_to_avid(str(report))
    request.addfinalizer(lambda: os.path.exists(avid_path) and os.remove(avid_path))

    with open(avid_path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_affects_names_the_target(exported_avid):
    """The run metadata is written as `start_run setup`, not `config`, so a
    reader looking for `config` finds nothing and `affects` comes out null."""
    assert exported_avid, "no AVID reports were written"

    for report in exported_avid:
        assert report["affects"] is not None
        assert report["affects"]["deployer"] == ["openai.OpenAICompatible"]
        assert report["affects"]["artifacts"][0]["name"] == "qwen2"


def test_description_names_the_target(exported_avid):
    for report in exported_avid:
        assert "qwen2" in report["description"]["value"]
        assert "openai.OpenAICompatible" in report["description"]["value"]


def test_export_survives_a_setup_row_missing_a_target_key(tmp_path, request):
    """A setup row without `plugins.target_name` must degrade, not abort the export.

    The description path already used `.get()`, so it degraded; the `Affects` block indexed the
    same metadata directly and raised `KeyError`, taking the whole export with it. Found by
    @feiiiiii5 reviewing this change.
    """
    source = "tests/_assets/report/report_test.report.jsonl"
    report = tmp_path / "missing_key.report.jsonl"
    with open(source, "r", encoding="utf-8") as src, open(
        report, "w", encoding="utf-8"
    ) as dst:
        for line in src:
            if not line.strip():
                continue
            entry = json.loads(line)
            if str(entry.get("entry_type", "")).startswith("start_run setup"):
                entry.pop("plugins.target_name", None)
            dst.write(json.dumps(entry) + "\n")

    avid_path = convert_to_avid(str(report))
    request.addfinalizer(lambda: os.path.exists(avid_path) and os.remove(avid_path))

    with open(avid_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    assert records, "the export produced no records at all"
    assert records[0]["affects"] is not None
