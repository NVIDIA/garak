# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# two tests:
# set buffs_include_original_prompt true
#  run test/lmrc.anthro
#  check that attempts w status 1 are original prompts + their lowercase versions
# set buffs_include_original_prompt false
#  run test/lmrc.anthro
#  check that attempts w status 1 are unique and have no uppercase characters

import json
import os
import tempfile
import uuid

import pytest

from garak import cli, _config

PREFIX = "test_buff_single" + str(uuid.uuid4())

_config.load_config()
REPORT_PATH = _config.transient.data_dir / _config.reporting.report_dir


def test_include_original_prompt():
    # https://github.com/python/cpython/pull/97015 to ensure Windows compatibility
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            """---
plugins:
    buffs_include_original_prompt: true
""".encode(
                "utf-8"
            )
        )
        tmp.close()
        cli.main(
            f"-m test -p test.Test -b lowercase.Lowercase --config {tmp.name} --report_prefix {PREFIX}".split()
        )
        os.remove(tmp.name)

    prompts = []
    with open(
        REPORT_PATH / f"{PREFIX}.report.jsonl", "r", encoding="utf-8"
    ) as reportfile:
        for line in reportfile:
            r = json.loads(line)
            if r["entry_type"] == "attempt" and r["status"] == 1:
                prompts.append(r["prompt"])
    nonupper_prompts = set([])
    other_prompts = set([])
    for prompt in prompts:
        text = prompt["turns"][-1]["content"]["text"]
        if text == text.lower() and text not in nonupper_prompts:
            nonupper_prompts.add(text)
        else:
            other_prompts.add(text)
    assert len(nonupper_prompts) >= len(other_prompts)
    assert len(nonupper_prompts) + len(other_prompts) == len(prompts)
    assert (
        set(map(str.lower, [p["turns"][-1]["content"]["text"] for p in prompts]))
        == nonupper_prompts
    )


def test_exclude_original_prompt():
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            """---
plugins:
    buffs_include_original_prompt: false
""".encode(
                "utf-8"
            )
        )
        tmp.close()
        cli.main(
            f"-m test -p test.Test -b lowercase.Lowercase --config {tmp.name} --report_prefix {PREFIX}".split()
        )
        os.remove(tmp.name)

    prompts = []
    with open(
        REPORT_PATH / f"{PREFIX}.report.jsonl", "r", encoding="utf-8"
    ) as reportfile:
        for line in reportfile:
            r = json.loads(line)
            if r["entry_type"] == "attempt" and r["status"] == 1:
                prompts.append(r["prompt"])
    for prompt in prompts:
        text = prompt["turns"][-1]["content"]["text"]
        assert text == text.lower()


@pytest.fixture(scope="session", autouse=True)
def cleanup(request):
    """Cleanup a testing directory once we are finished."""

    def remove_buff_reports():
        files = [
            REPORT_PATH / f"{PREFIX}.report.jsonl",
            REPORT_PATH / f"{PREFIX}.report.html",
            REPORT_PATH / f"{PREFIX}.hitlog.jsonl",
        ]
        for file in files:
            if os.path.exists(file):
                os.remove(file)

    request.addfinalizer(remove_buff_reports)
