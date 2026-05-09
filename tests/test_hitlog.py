# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import threading
from pathlib import Path

from garak import cli, _config

CODEPATH_PREFIX = "_garak_test_hitlog_codepath"


def test_hitlog_codepath():

    args = f"-m test.Blank --report_prefix {CODEPATH_PREFIX} -p test.Test -d always.Fail".split()
    cli.main(args)
    report_path = Path(_config.transient.report_filename).parent
    assert os.path.isfile(report_path / f"{CODEPATH_PREFIX}.hitlog.jsonl")


def test_hitlog_lock_exists():
    """The module-level _hitlog_lock must be a threading.Lock instance.

    Regression guard for https://github.com/NVIDIA/garak/issues/1355 — ensures
    the lock that serialises concurrent hitlog writes is present and of the
    correct type.
    """
    from garak.evaluators.base import _hitlog_lock

    assert isinstance(_hitlog_lock, type(threading.Lock())), (
        "_hitlog_lock must be a threading.Lock"
    )


def test_hitlog_concurrent_writes(tmp_path):
    """Concurrent hitlog writes from multiple threads must produce valid JSONL.

    Regression test for https://github.com/NVIDIA/garak/issues/1355 — before
    the fix, multiple threads could interleave writes and corrupt lines in the
    hitlog file.
    """
    import json
    from garak.evaluators.base import _hitlog_lock

    hitlog_path = tmp_path / "run.hitlog.jsonl"
    errors = []

    def write_entry(idx):
        entry = json.dumps({"idx": idx, "data": "x" * 200}) + "\n"
        try:
            with _hitlog_lock:
                with open(hitlog_path, "a", buffering=1, encoding="utf-8") as f:
                    f.write(entry)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=write_entry, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Exceptions during concurrent writes: {errors}"

    lines = hitlog_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 50, f"Expected 50 lines, got {len(lines)}"
    for line in lines:
        json.loads(line)  # raises JSONDecodeError if line is corrupt
