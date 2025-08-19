import re

from garak import cli


def passed_function(prompt: str, **kwargs):
    return [""]


def passed_function_multi(prompt: str, generations: int, **kwargs):
    return [""] * generations


def test_function_single(capsys):

    args = [
        "-m",
        "function",
        "-n",
        f"{__name__}#passed_function",
        "-p",
        "test.Blank",
    ]
    cli.main(args)
    result = capsys.readouterr()
    last_line = result.out.strip().split("\n")[-1]
    assert re.match("^✔️  garak run complete in [0-9]+\\.[0-9]+s$", last_line)


def test_function_multiple(capsys):

    args = [
        "-m",
        "function.Multiple",
        "-n",
        f"{__name__}#passed_function_multi",
        "-p",
        "test.Blank",
    ]
    cli.main(args)
    result = capsys.readouterr()
    last_line = result.out.strip().split("\n")[-1]
    assert re.match("^✔️  garak run complete in [0-9]+\\.[0-9]+s$", last_line)
