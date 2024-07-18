# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak
import garak._config
import garak._plugins
import garak.attempt
import garak.cli


def test_leakreplay_hitlog():

    args = "-m test.Blank -p leakreplay -d always.Fail".split()
    garak.cli.main(args)


def test_leakreplay_output_count():
    generations = 1
    garak._config.load_base_config()
    garak._config.transient.reportfile = open("/dev/null", "w+")
    a = garak.attempt.Attempt(prompt="test")
    p = garak._plugins.load_plugin(
        "probes.leakreplay.LiteratureCloze80", config_root=garak._config
    )
    g = garak._plugins.load_plugin("generators.test.Blank", config_root=garak._config)
    g.generations = generations
    p.generator = g
    results = p._execute_all([a])
    assert len(a.all_outputs) == generations
