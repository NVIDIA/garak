import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).parents[1]
TOOL_ROOT = REPO_ROOT / "tools" / "packagehallucination"
LANGUAGE_TOOL_PATHS = {
    "javascript": TOOL_ROOT / "javascript" / "main.py",
    "python": TOOL_ROOT / "python" / "main.py",
    "ruby": TOOL_ROOT / "ruby" / "main.py",
}

sys.path.insert(0, str(TOOL_ROOT))

from _common import emit_record, write_jsonl  # noqa: E402


def load_tool(language):
    spec = importlib.util.spec_from_file_location(
        f"packagehallucination_{language}_main",
        LANGUAGE_TOOL_PATHS[language],
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_emit_record_uses_standard_fields_and_iso_date():
    record = emit_record("requests", "2011-02-14")

    assert record == {
        "text": "requests",
        "package_first_seen": "2011-02-14",
    }, "package record should use the standard dataset schema"


def test_emit_record_coerces_invalid_or_absent_dates_to_none():
    assert (
        emit_record("requests", None)["package_first_seen"] is None
    ), "absent package date should be represented as null"
    assert (
        emit_record("requests", "not a date")["package_first_seen"] is None
    ), "malformed package date should be represented as null"


def test_write_jsonl_emits_standard_record(tmp_path):
    output_path = tmp_path / "packages.jsonl"
    write_jsonl([emit_record("requests", "2011-02-14")], output_path)

    record = json.loads(output_path.read_text(encoding="utf-8"))
    assert record == {
        "package_first_seen": "2011-02-14",
        "text": "requests",
    }, "JSONL output should contain the standard package record"


def test_refactored_tools_expose_identical_cli_flags():
    flag_sets = {}
    for language, tool_path in LANGUAGE_TOOL_PATHS.items():
        result = subprocess.run(
            [sys.executable, str(tool_path), "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        flag_sets[language] = set(re.findall(r"--[a-z-]+", result.stdout))

    expected_flags = {"--help", "--input", "--output", "--format"}
    assert {frozenset(flags) for flags in flag_sets.values()} == {
        frozenset(expected_flags)
    }, "refactored tools should expose the same CLI flag names"


def test_refactored_tools_write_jsonl_records(monkeypatch, tmp_path):
    for language in LANGUAGE_TOOL_PATHS:
        module = load_tool(language)
        output_path = tmp_path / f"{language}.jsonl"

        if language == "python":
            monkeypatch.setattr(module, "get_all_packages", lambda: ["requests"])
        else:
            monkeypatch.setattr(
                module, "get_all_packages", lambda input_file: ["requests"]
            )

        monkeypatch.setattr(
            module,
            "build_records",
            lambda packages: [emit_record(packages[0], "2011-02-14")],
        )

        assert (
            module.main(["--output", str(output_path)]) == 0
        ), f"{language} tool should complete with package data"
        record = json.loads(output_path.read_text(encoding="utf-8"))
        assert record == {
            "package_first_seen": "2011-02-14",
            "text": "requests",
        }, f"{language} tool should write standard JSONL records"


def test_refactored_tools_fail_closed_on_empty_package_feed(
    monkeypatch, tmp_path, capsys
):
    for language in LANGUAGE_TOOL_PATHS:
        module = load_tool(language)
        output_path = tmp_path / f"{language}.jsonl"

        if language == "python":
            monkeypatch.setattr(module, "get_all_packages", lambda: [])
        else:
            monkeypatch.setattr(module, "get_all_packages", lambda input_file: [])

        assert (
            module.main(["--output", str(output_path)]) == 1
        ), f"{language} tool should fail on an empty package feed"
        captured = capsys.readouterr()
        assert (
            "refusing to write an empty dataset" in captured.err
        ), f"{language} tool should explain why it did not write output"
        assert (
            not output_path.exists()
        ), f"{language} tool should not create an output file for an empty feed"
