"""Regression tests for preserving report files during CI rebuilds."""

import errno
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from garak import _config
from garak.analyze.ci_calculator import update_eval_entries_with_ci

CI_RESULTS = {("test.Test", "always.Pass"): (10.0, 90.0)}


@pytest.fixture(autouse=True)
def loaded_config():
    _config.load_base_config()
    _config.reporting.bootstrap_num_iterations = 10


@pytest.fixture
def report(tmp_path):
    report_file = tmp_path / "sample.report.jsonl"
    entries = [
        {
            "entry_type": "init",
            "garak_version": "0.17",
            "start_time": "2026-01-01T00:00:00",
            "run": "test-run-uuid",
        },
        {
            "entry_type": "start_run setup",
            "plugins.probe_spec": "test.Test",
            "plugins.target_type": "test",
            "plugins.target_name": "test-target",
        },
        {
            "entry_type": "eval",
            "probe": "test.Test",
            "detector": "always.Pass",
            "passed": 75,
            "total_evaluated": 100,
        },
        {
            "entry_type": "digest",
            "eval": {
                "test": {
                    "test.Test": {"always.Pass": {"passed": 75, "total_evaluated": 100}}
                }
            },
        },
    ]
    report_file.write_text(
        "".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8"
    )
    return report_file


@pytest.mark.parametrize("writer", ["update", "rebuild"])
@pytest.mark.parametrize("alias", ["absolute", "relative", "symlink", "hardlink"])
def test_reject_output_referring_to_input(report, alias, writer, monkeypatch, capsys):
    original = report.read_bytes()
    output = report
    if alias == "relative":
        monkeypatch.chdir(report.parent)
        output = Path(report.name)
    elif alias in ("symlink", "hardlink"):
        output = report.parent / "alias.jsonl"
        try:
            if alias == "symlink":
                output.symlink_to(report)
            else:
                output.hardlink_to(report)
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"{alias} is unavailable: {error}")

    existing_paths = set(report.parent.iterdir())
    if writer == "update":
        with pytest.raises(ValueError, match="Output path refers to the input report"):
            update_eval_entries_with_ci(str(report), CI_RESULTS, str(output))
    else:
        from garak.analyze.rebuild_cis import rebuild_cis_for_report

        result = rebuild_cis_for_report(str(report), output_path=str(output))
        assert result == 1, "Rebuild must reject an output that aliases the input"
        assert (
            "Output path refers to the input report" in capsys.readouterr().out
        ), "Rebuild must explain why the output was rejected"

    assert report.read_bytes() == original, "Rejected output must preserve the input"
    assert output.read_bytes() == original, "Aliases must still contain the input"
    assert (
        set(report.parent.iterdir()) == existing_paths
    ), "No temporary file may remain"


@pytest.mark.parametrize("filename", ["sample.report.jsonl", "sample.tmp", "sample"])
def test_in_place_update_uses_unique_temporary_file(report, filename):
    report = report.rename(report.parent / filename)
    existing_temp = report.with_suffix(".tmp")
    if existing_temp != report:
        existing_temp.write_text("Keep this existing file", encoding="utf-8")
    existing_paths = set(report.parent.iterdir())

    update_eval_entries_with_ci(str(report), CI_RESULTS)

    entries = [
        json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()
    ]
    assert len(entries) == 3, "Metadata and the updated evaluation must remain"
    assert entries[2]["confidence_lower"] == 0.1, "Lower CI must be written"
    assert entries[2]["confidence_upper"] == 0.9, "Upper CI must be written"
    if existing_temp != report:
        assert (
            existing_temp.read_text(encoding="utf-8") == "Keep this existing file"
        ), "Existing temporary files must not be overwritten"
    assert (
        set(report.parent.iterdir()) == existing_paths
    ), "No temporary file may remain"


@pytest.mark.parametrize(
    "failure", ["malformed_json", "replace_error", "readonly_replace_error"]
)
def test_failed_in_place_update_preserves_source_and_cleans_up(
    report, failure, monkeypatch
):
    if failure == "malformed_json":
        with report.open("a", encoding="utf-8") as report_file:
            report_file.write("invalid JSON\n")
        expected_error = json.JSONDecodeError
        expected_message = "Malformed JSON"
    else:

        def fail_replace(self, target):
            raise OSError("Cannot replace report")

        monkeypatch.setattr(Path, "replace", fail_replace)
        expected_error = OSError
        expected_message = "Error updating report file.*Cannot replace report"
        if failure == "readonly_replace_error":
            report.chmod(stat.S_IRUSR)
            original_unlink = Path.unlink

            def reject_readonly_unlink(self, *args, **kwargs):
                if self.exists() and not self.stat().st_mode & stat.S_IWUSR:
                    raise PermissionError("Windows cannot delete read-only files")
                return original_unlink(self, *args, **kwargs)

            monkeypatch.setattr(Path, "unlink", reject_readonly_unlink)

    original = report.read_bytes()
    existing_paths = set(report.parent.iterdir())

    with pytest.raises(expected_error, match=expected_message):
        update_eval_entries_with_ci(str(report), CI_RESULTS)

    assert report.read_bytes() == original, "Failed updates must preserve the input"
    assert (
        set(report.parent.iterdir()) == existing_paths
    ), "Failed updates must clean up"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits required")
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_in_place_update_preserves_permissions(report, mode):
    report.chmod(mode)

    update_eval_entries_with_ci(str(report), CI_RESULTS)

    assert (
        stat.S_IMODE(report.stat().st_mode) == mode
    ), "Report permissions must be kept"


def test_in_place_update_with_long_filename(report):
    try:
        report = report.rename(report.parent / ("r" * 230 + ".report.jsonl"))
    except OSError as error:
        if error.errno == errno.ENAMETOOLONG or getattr(error, "winerror", None) == 206:
            pytest.skip("Filesystem cannot create this long report filename")
        raise

    update_eval_entries_with_ci(str(report), CI_RESULTS)

    entries = [
        json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()
    ]
    assert entries[2]["confidence_lower"] == 0.1, "Long filenames must support updates"
    assert list(report.parent.iterdir()) == [report], "No temporary file may remain"


@pytest.mark.parametrize("overwrite", [False, True])
def test_rebuild_cli_preserves_same_path_input(
    report, overwrite, tmp_path, monkeypatch
):
    report = report.rename(report.with_suffix(".tmp"))
    original = report.read_bytes()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    args = [
        sys.executable,
        "-m",
        "garak.analyze.rebuild_cis",
        "-r",
        str(report),
        "--bootstrap_num_iterations",
        "10",
    ]
    args.extend(["-w"] if overwrite else ["-o", str(report)])

    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")

    if overwrite:
        assert result.returncode == 0, result.stdout + result.stderr
        entries = [
            json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()
        ]
        eval_entry = next(entry for entry in entries if entry["entry_type"] == "eval")
        assert "confidence_lower" in eval_entry, "CLI overwrite must update CIs"
        assert entries[-1]["entry_type"] == "digest", "CLI must rebuild the digest"
    else:
        assert result.returncode == 1, "CLI must reject the same input and output"
        assert (
            "Use --overwrite" in result.stdout
        ), "CLI must explain the safe alternative"
        assert report.read_bytes() == original, "CLI rejection must preserve the input"
