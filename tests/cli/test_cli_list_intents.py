# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import re

import pytest

from garak import cli

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _clean(output: str) -> str:
    return ANSI_RE.sub("", output)


def test_list_intents_groups_typology_and_marks_content(capsys):
    cli.main(["--list_intents"])

    output = _clean(capsys.readouterr().out)
    assert "C: Chat" in output, "chat intents must have a named branch heading"
    assert "T: Tasks" in output, "task intents must have a named branch heading"
    assert "M: Meta" in output, "meta intents must have a named branch heading"
    assert "S: Safety" in output, "safety intents must have a named branch heading"
    assert (
        "C006 ✅ - Anthropomorphise" in output
    ), "an intent with a mapped detector must be marked as having content"
    assert (
        "T001 ✅ - Logic problems" in output
    ), "an intent with a default stub must be marked as having content"
    assert (
        "M009data ✅ - Disclose training data" in output
    ), "an intent with a stub file must be marked as having content"
    assert (
        "C001 - Engage in idle chat" in output
    ), "an intent without detectors or stubs must be marked as lacking content"


def test_list_intents_filters_to_specified_subtree(capsys):
    cli.main(["--list_intents", "--spec", "intent:S005"])

    output = _clean(capsys.readouterr().out)
    assert "S005hate" in output, "intent:S005 must include descendant intents"
    assert "S005bully" in output, "intent:S005 must include every matching descendant"
    assert "S004" not in output, "intent:S005 must exclude neighbouring subtrees"


def test_list_intents_applies_spec_exclusions(capsys):
    cli.main(["--list_intents", "--spec", "intent:S,-intent:S005"])

    output = _clean(capsys.readouterr().out)
    assert "S004" in output, "the included safety branch must remain visible"
    assert "S005" not in output, "an excluded subtree must not be listed"


def test_list_intents_exclusion_only_starts_from_full_typology(capsys):
    cli.main(["--list_intents", "--spec=-intent:S005"])

    output = _clean(capsys.readouterr().out)
    assert "C: Chat" in output, "an exclusion-only filter must retain chat intents"
    assert "T: Tasks" in output, "an exclusion-only filter must retain task intents"
    assert "M: Meta" in output, "an exclusion-only filter must retain meta intents"
    assert "S004" in output, "unexcluded safety intents must remain visible"
    assert "S005" not in output, "the excluded subtree must not be listed"


@pytest.mark.parametrize(
    ("intent_spec", "expected"),
    [
        ("intent:*,intent:S005", "C: Chat"),
        ("-intent:all,-intent:S005", "No intents match the provided filter"),
    ],
)
def test_list_intents_combines_all_sentinel(intent_spec, expected, capsys):
    cli.main(["--list_intents", f"--spec={intent_spec}"])

    output = _clean(capsys.readouterr().out)
    assert expected in output, "all-intents sentinels must compose with other selectors"


def test_list_intents_reports_an_empty_selection(capsys):
    cli.main(["--list_intents", "--spec", "intent:S005,-intent:S005", "-v"])

    output = _clean(capsys.readouterr().out)
    assert "No intents match the provided filter" in output


def test_list_intents_verbose_includes_descriptions(capsys):
    cli.main(["--list_intents", "--spec", "intent:S005bully", "-v"])

    output = _clean(capsys.readouterr().out)
    assert re.search(r"\|\s*code\s*\|", output), "verbose output must include codes"
    assert re.search(r"\|\s*name\s*\|", output), "verbose output must include names"
    assert re.search(
        r"\|\s*description\s*\|", output
    ), "verbose output must include descriptions"
    assert re.search(
        r"\|\s*content\s*\|", output
    ), "verbose output must include content status"
    assert (
        "Produce targeted personal attacks" in output
    ), "verbose output must show the typology description"


def test_list_intents_invalid_code_points_to_discovery_command(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--list_intents", "--spec", "intent:S999"])

    output = _clean(capsys.readouterr().out)
    assert excinfo.value.code == 1, "invalid intent input must return a failure status"
    assert "S999" in output, "invalid intent errors must identify the rejected code"
    assert (
        "--list_intents" in output
    ), "invalid intent errors must point users to the discovery command"


@pytest.mark.parametrize("intent_spec", ["intent:", "-intent:"])
def test_list_intents_rejects_empty_code(intent_spec, capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--list_intents", f"--spec={intent_spec}"])

    output = _clean(capsys.readouterr().out)
    assert excinfo.value.code == 1, "empty intent input must return a failure status"
    assert "requires a code" in output, "empty intent errors must explain the omission"
    assert (
        "--list_intents" in output
    ), "empty intent errors must point users to the discovery command"
    assert (
        "C: Chat" not in output
    ), "invalid filters must not fall back to listing all intents"


def test_list_intents_rejects_empty_code_from_config(tmp_path, capsys):
    config_path = tmp_path / "empty_intent.yaml"
    config_path.write_text(
        "---\nrun:\n  spec:\n    include:\n      - intent: ''\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--list_intents", "--config", str(config_path)])

    output = _clean(capsys.readouterr().out)
    assert excinfo.value.code == 1, "empty config intent must return a failure status"
    assert "requires a code" in output, "config errors must explain the omission"
