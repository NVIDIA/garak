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
