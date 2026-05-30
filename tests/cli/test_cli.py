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
