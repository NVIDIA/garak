# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import tempfile

from garak import _config
import garak._plugins


def test_system_prompt():
    _config.run.system_prompt = "Test system prompt"
    _config.system.parallel_attempts = 1
    temp_report_file = tempfile.NamedTemporaryFile(
        mode="w+", delete=False, encoding="utf-8"
    )
    _config.transient.reportfile = temp_report_file
    _config.transient.report_filename = temp_report_file.name

    p = garak._plugins.load_plugin("probes.test.Blank")
    g = garak._plugins.load_plugin("generators.test.Blank")
    p.generations = 1
    results = p.probe(g)
    assert (
        results[0].conversations[0].turns[0].role == "system"
    ), "First message of the conversation should be from 'system'"
