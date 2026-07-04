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
        ["-m", "test", "-p", "all", "-d", "always.Pass", "-g", "1", "--narrow_output"]
    )
    result = capsys.readouterr()
    last_line = result.out.strip().split("\n")[-1]
    assert re.match("^✔️  garak run complete in [0-9]+\\.[0-9]+s$", last_line)


def test_module_with_only_inactive_probes_gives_clear_message(capsys):
    # issue #830: -p test names a module whose probes are all marked inactive,
    # so the user should get a clear "all inactive" message rather than the
    # generic "Unknown probes" error
    cli.main(["-m", "test", "-p", "test", "-g", "1", "--narrow_output"])
    result = capsys.readouterr()
    output = ANSI_ESCAPE.sub("", result.out)
    assert "inactive" in output
    assert "Unknown probes" not in output


def test_run_all_active_detectors(capsys):
    cli.main(
        [
            "-m",
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
