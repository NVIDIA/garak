# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

from garak.analyze.count_tokens import count_tokens


def _write_report(tmp_path, prompt, generations):
    report_path = tmp_path / "count_tokens.report.jsonl"
    entries = [
        {"run.generations": generations},
        {
            "status": 2,
            "prompt": prompt,
            "outputs": [],
        },
    ]
    report_path.write_text(
        "".join(json.dumps(entry) + "\n" for entry in entries),
        encoding="utf-8",
    )
    return report_path


def test_count_tokens_counts_nested_prompt_text(tmp_path, capsys):
    prompt_text = "known prompt text"
    generations = 3
    report_path = _write_report(
        tmp_path,
        {
            "role": "user",
            "content": {"text": prompt_text},
        },
        generations,
    )

    count_tokens(str(report_path))

    output = capsys.readouterr().out
    assert f"Calls: {generations}" in output
    assert f"Input chars: {len(prompt_text) * generations}" in output


def test_count_tokens_accepts_legacy_string_prompt(tmp_path, capsys):
    prompt_text = "legacy prompt"
    report_path = _write_report(tmp_path, prompt_text, generations=2)

    count_tokens(str(report_path))

    output = capsys.readouterr().out
    assert f"Input chars: {len(prompt_text) * 2}" in output
