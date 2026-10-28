# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the garak console entry point, garak.__main__"""

import os
import subprocess
import sys


def _run_entrypoint_with_legacy_stdout(body: str) -> subprocess.CompletedProcess:
    """Invoke main() the way the console script does, with a non-UTF-8 stdout.

    The `garak` console script is declared as `garak.__main__:main`, so it calls
    main() directly and never runs the `if __name__ == "__main__"` block.
    """
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "cp1252"
    env.pop("PYTHONUTF8", None)
    return subprocess.run(
        [sys.executable, "-c", body], capture_output=True, env=env, timeout=120
    )


def test_entrypoint_emits_non_ascii_on_legacy_stdout():
    """main() must make stdout UTF-8 so plugin-listing emoji survive a redirect"""
    result = _run_entrypoint_with_legacy_stdout(
        "import garak.cli\n"
        "garak.cli.main = lambda argv: print('\\U0001F31F')\n"
        "from garak.__main__ import main\n"
        "main()\n"
    )
    assert result.returncode == 0, (
        "console entry point must not fail on a non-UTF-8 stdout: "
        f"{result.stderr.decode(errors='replace')}"
    )
    assert (
        "\U0001F31F".encode("utf-8") in result.stdout
    ), "non-ASCII output must reach stdout intact rather than being truncated"
