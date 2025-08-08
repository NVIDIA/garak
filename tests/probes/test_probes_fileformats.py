# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import garak._config
import garak._plugins

import garak.probes.base
import garak.probes.fileformats
import garak.attempt


def test_hf_files_load():
    p = garak.probes.fileformats.HF_Files()
    assert isinstance(p, garak.probes.base.Probe)


# files could be their own thing if Turns start taking named/typed entries
def test_hf_files_hf_repo():
    p = garak._plugins.load_plugin("probes.fileformats.HF_Files")
    garak._config.plugins.generators["huggingface"] = {
        "Model": {"name": "gpt2", "hf_args": {"device": "cpu"}},
    }
    g = garak._plugins.load_plugin(
        "generators.huggingface.Model", config_root=garak._config
    )
    r = p.probe(g)
    assert isinstance(r, list), ".probe should return a list"
    assert len(r) == 1, "HF_Files.probe() should return one attempt"
    assert isinstance(
        r[0], garak.attempt.Attempt
    ), "HF_Files.probe() must return an Attempt"
    assert isinstance(r[0].outputs, list), "File list scan should return a list"
    assert len(r[0].outputs) > 0, "File list scan should return list of filenames"
    for filename in r[0].outputs:
        assert isinstance(
            filename.text, str
        ), "File list scan should return list of Turns with .text being string filenames"
        assert os.path.isfile(
            filename.text
        ), "List of HF_Files paths should all be real files"
