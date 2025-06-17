# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import garak
import garak._config
import garak._plugins
import garak.attempt
import garak.cli
import garak.probes.leakreplay


def test_leakreplay_hitlog():

    args = "-m test.Blank -p leakreplay -d always.Fail".split()
    garak.cli.main(args)


def test_leakreplay_output_count():
    generations = 1
    garak._config.load_base_config()
    garak._config.transient.reportfile = open(os.devnull, "w+", encoding="utf-8")
    garak._config.plugins.probes["leakreplay"]["generations"] = generations
    a = garak.attempt.Attempt(prompt="test")
    p = garak._plugins.load_plugin(
        "probes.leakreplay.LiteratureCloze", config_root=garak._config
    )
    g = garak._plugins.load_plugin("generators.test.Blank", config_root=garak._config)
    p.generator = g
    results = p._execute_all([a])
    assert len(a.all_outputs) == generations


def test_leakreplay_handle_incomplete_attempt():
    p = garak.probes.leakreplay.LiteratureCloze()
    a = garak.attempt.Attempt(prompt="IS THIS BROKEN")
    a.outputs = ["", None]
    p._postprocess_hook(a)
