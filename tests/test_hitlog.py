# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path

from garak import cli, _config

CODEPATH_PREFIX = "_garak_test_hitlog_codepath"


def test_hitlog_codepath():

    args = f"-m test.Blank --report_prefix {CODEPATH_PREFIX} -p test.Test -d always.Fail".split()
    cli.main(args)
    report_path = Path(_config.transient.report_filename).parent
    assert os.path.isfile(report_path / f"{CODEPATH_PREFIX}.hitlog.jsonl")
