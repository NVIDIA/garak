"""Aggregation must not overwrite any of its input reports."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.parametrize("source_index", [0, 1])
@pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink"])
def test_aggregate_rejects_output_aliasing_input(tmp_path, source_index, alias):
    assets = Path(__file__).parents[1] / "_assets" / "analyze"
    sources = [tmp_path / "first.jsonl", tmp_path / "second.jsonl"]
    for source, fixture in zip(sources, ["test.report.jsonl", "quack.report.jsonl"]):
        shutil.copyfile(assets / fixture, source)
    originals = [source.read_bytes() for source in sources]
    source = sources[source_index]
    output = source

    if alias == "relative":
        directory = tmp_path / "nested"
        directory.mkdir()
        output = directory / ".." / source.name
    elif alias in ("symlink", "hardlink"):
        output = tmp_path / "alias.jsonl"
        try:
            if alias == "symlink":
                output.symlink_to(source)
            else:
                output.hardlink_to(source)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"Cannot create {alias} on this platform: {error}")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak.analyze.aggregate_reports",
            "-o",
            str(output),
            *(str(path) for path in sources),
        ],
        capture_output=True,
        text=True,
    )

    assert [
        path.read_bytes() for path in sources
    ] == originals, (
        "Rejecting an output that aliases an input must preserve every source byte"
    )
    assert result.returncode == 2, "Invalid output should produce an argparse error"
    assert (
        "Output path must not refer to an input report" in result.stderr
    ), "The error should explain why the output path is invalid"
