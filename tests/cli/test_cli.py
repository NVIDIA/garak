import argparse
import json
import logging
import re
import pytest
import os

from garak import __app__, __description__, __version__, cli, _config

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def test_version_command(capsys):
    cli.main(["--version"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    assert "garak" in output
    assert f"v{__version__}" in output
    assert len(output.strip().split("\n")) == 1


def test_probe_list(capsys):
    cli.main(["--list_probes"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    for line in output.strip().split("\n"):
        assert re.match(
            r"^probes: [a-z0-9_]+(\.[A-Za-z0-9_]+)?( 🌟)?( 💤)?$", line
        ) or line.startswith(f"{__app__} {__description__}")


def test_detector_list(capsys):
    cli.main(["--list_detectors"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    for line in output.strip().split("\n"):
        assert re.match(
            r"^detectors: [a-z0-9_]+(\.[A-Za-z0-9_]+)?( 🌟)?( 💤)?$", line
        ) or line.startswith(f"{__app__} {__description__}")


def test_generator_list(capsys):
    cli.main(["--list_generators"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    for line in output.strip().split("\n"):
        assert re.match(
            r"^generators: [a-z0-9_]+(\.[A-Za-z0-9_]+)?( 🌟)?( 💤)?$", line
        ) or line.startswith(f"{__app__} {__description__}")


def test_buff_list(capsys):
    cli.main(["--list_buffs"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    for line in output.strip().split("\n"):
        assert re.match(
            r"^buffs: [a-z0-9_]+(\.[A-Za-z0-9_]+)?( 🌟)?( 💤)?$", line
        ) or line.startswith(f"{__app__} {__description__}")


def test_run_all_active_probes(capsys):
    cli.main(
        ["-t", "test", "-p", "all", "-d", "always.Pass", "-g", "1", "--narrow_output"]
    )
    result = capsys.readouterr()
    last_line = result.out.strip().split("\n")[-1]
    assert re.match("^✔️  garak run complete in [0-9]+\\.[0-9]+s$", last_line)


def test_module_with_only_inactive_probes_gives_clear_message(capsys):
    # issue #830: -p test names a module whose probes are all marked inactive,
    # so the user should get a clear "all inactive" message rather than the
    # generic "Unknown probes" error
    cli.main(["-t", "test", "-p", "test", "-g", "1", "--narrow_output"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    assert "inactive" in output
    assert "Unknown probes" not in output


def test_inactive_module_flagged_when_active_probe_also_selected(capsys):
    # issue #830: an all-inactive module must still be flagged even when an
    # active family is selected too (regression guard for the run.spec refactor)
    cli.main(["-t", "test", "-p", "dan,test", "-d", "always.Pass", "-g", "1", "--narrow_output"])
    output = ANSI_ESCAPE.sub("", capsys.readouterr().out)
    assert "inactive" in output, "all-inactive module must be flagged, not silently dropped"


def test_inactive_module_skipped_with_skip_unknown(capsys):
    cli.main(
        [
            "-t",
            "test",
            "-p",
            "dan,test",
            "-d",
            "always.Pass",
            "-g",
            "1",
            "--narrow_output",
            "--skip_unknown",
        ]
    )
    output = ANSI_ESCAPE.sub("", capsys.readouterr().out)
    last_line = output.strip().split("\n")[-1]
    assert re.match(
        "^✔️  garak run complete in [0-9]+\\.[0-9]+s$", last_line
    ), "--skip_unknown must warn about the inactive module and complete the run"


def test_run_all_active_detectors(capsys):
    cli.main(
        [
            "-t",
            "test",
            "-p",
            "blank.BlankPrompt",
            "-d",
            "all",
            "-g",
            "1",
            "--narrow_output",
            "--skip_unknown",
        ]
    )
    result = capsys.readouterr()
    last_line = result.out.strip().split("\n")[-1]
    assert re.match("^✔️  garak run complete in [0-9]+\\.[0-9]+s$", last_line)


def test_plugin_option_file_missing_reports_path():
    # a missing --<plugin>_option_file must name the offending path, not the flag,
    # so the user can find the file they meant
    bad_path = os.path.join("no", "such", "options.json")
    args = argparse.Namespace(generator_option_file=bad_path)
    with pytest.raises(FileNotFoundError) as excinfo:
        cli.parse_cli_plugin_config("generator", args)
    message = str(excinfo.value)
    assert bad_path in message, "error should name the offending path"
    assert (
        "generator_option_file" not in message
    ), "error should not name the argparse flag instead of the path"


def test_plugin_option_file_bad_json_warning_is_wellformed(tmp_path, caplog):
    # a malformed --<plugin>_option_file must warn with the file path and the raw
    # parser message, with no stray set-literal braces around the error
    options_file = tmp_path / "options.json"
    options_file.write_text("this is not json", encoding="utf-8")
    args = argparse.Namespace(generator_option_file=str(options_file))
    with caplog.at_level(logging.WARNING):
        with pytest.raises(json.JSONDecodeError):
            cli.parse_cli_plugin_config("generator", args)
    message = caplog.text
    assert str(options_file) in message, "warning should name the file path"
    assert (
        "generator_option_file" not in message
    ), "warning should name the file path, not the argparse flag"
    assert "{" not in message, "warning should not wrap the error in a set literal"


def test_legacy_probes_and_run_spec_select_same_run(capsys):
    """The deprecated -p flag and the unified --spec must drive the same
    end-to-end run: identical probe + detector selection, both completing."""
    complete = "^✔️  garak run complete in [0-9]+\\.[0-9]+s$"

    cli.main(
        [
            "-t",
            "test",
            "-p",
            "test.Blank",
            "-d",
            "always.Pass",
            "-g",
            "1",
            "--narrow_output",
        ]
    )
    legacy_last = capsys.readouterr().out.strip().split("\n")[-1]
    legacy_spec = dict(_config.run.spec)
    legacy_detector = _config.plugins.detector_spec

    cli.main(
        [
            "-t",
            "test",
            "--spec",
            "probes.test.Blank",
            "-d",
            "always.Pass",
            "-g",
            "1",
            "--narrow_output",
        ]
    )
    new_last = capsys.readouterr().out.strip().split("\n")[-1]
    new_spec = dict(_config.run.spec)
    new_detector = _config.plugins.detector_spec

    assert re.match(
        complete, legacy_last
    ), f"legacy -p run did not complete; last line: {legacy_last!r}"
    assert re.match(
        complete, new_last
    ), f"--spec run did not complete; last line: {new_last!r}"
    assert legacy_spec == new_spec == {
        "include": ["probes.test.Blank"],
        "exclude": [],
    }, f"old and new formats must resolve to the same run.spec; got {legacy_spec!r} vs {new_spec!r}"
    assert (
        legacy_detector == new_detector == "always.Pass"
    ), f"both formats must select the same detector; got {legacy_detector!r} vs {new_detector!r}"


def test_spec_short_flag_matches_long(capsys):
    """`-S` must be an alias of `--spec`, resolving to the same run.spec."""
    cli.main(["--spec", "probes.test.Blank", "--list_config"])
    long_spec = dict(_config.run.spec)

    cli.main(["-S", "probes.test.Blank", "--list_config"])
    short_spec = dict(_config.run.spec)

    assert short_spec == long_spec == {
        "include": ["probes.test.Blank"],
        "exclude": [],
    }, f"-S must alias --spec; got {short_spec!r} vs {long_spec!r}"


def test_spec_unquoted_multiple_selectors(capsys):
    """A comma-separated --spec needs no shell quoting: a single unquoted
    token (no spaces) must parse into multiple selectors."""
    cli.main(["--spec", "probes.test.Blank,probes.test.Test", "--list_config"])
    assert dict(_config.run.spec) == {
        "include": ["probes.test.Blank", "probes.test.Test"],
        "exclude": [],
    }, "unquoted comma-separated --spec must yield both selectors"


def test_spec_whitespace_rejected(capsys):
    """Whitespace between selectors is rejected so quotes stay optional."""
    with pytest.raises(SystemExit):
        cli.main(["--spec", "probes.test.Blank, probes.test.Test", "--list_config"])
    assert "invalid --spec" in capsys.readouterr().out, "spaced --spec must be rejected"
