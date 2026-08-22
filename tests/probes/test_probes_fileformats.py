# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import huggingface_hub.errors

import garak._config
import garak._plugins

import garak.probes.base
import garak.probes.fileformats
import garak.attempt


def _local_hf_generator(name):
    generator_class = type(
        "Model", (), {"__module__": "garak.generators.huggingface"}
    )
    generator = generator_class()
    generator.name = str(name)
    return generator


def test_hf_files_load():
    p = garak.probes.fileformats.HF_Files()
    assert isinstance(p, garak.probes.base.Probe)


def test_hf_files_local_directory(tmp_path, monkeypatch):
    model_file = tmp_path / "config.json"
    nested_model_file = tmp_path / "weights" / "model.safetensors"
    nested_model_file.parent.mkdir()
    model_file.write_text("{}", encoding="utf-8")
    nested_model_file.write_bytes(b"test model data")

    def fail_list_repo_files(*args, **kwargs):
        raise AssertionError("local model paths should not be listed through HF Hub")

    monkeypatch.setattr(
        garak.probes.fileformats.huggingface_hub,
        "list_repo_files",
        fail_list_repo_files,
    )

    p = garak.probes.fileformats.HF_Files()
    r = p.probe(_local_hf_generator(tmp_path))

    assert isinstance(r, list), ".probe should return a list"
    assert len(r) == 1, "HF_Files.probe() should return one attempt"
    assert isinstance(
        r[0], garak.attempt.Attempt
    ), "HF_Files.probe() must return an Attempt"
    assert sorted(filename.text for filename in r[0].outputs) == sorted(
        [str(model_file.resolve()), str(nested_model_file.resolve())]
    )


def test_hf_files_empty_local_directory(tmp_path, monkeypatch):
    def fail_list_repo_files(*args, **kwargs):
        raise AssertionError("local model paths should not be listed through HF Hub")

    monkeypatch.setattr(
        garak.probes.fileformats.huggingface_hub,
        "list_repo_files",
        fail_list_repo_files,
    )

    p = garak.probes.fileformats.HF_Files()
    assert p.probe(_local_hf_generator(tmp_path)) == []


def test_hf_files_hf_hub_offline_mode(monkeypatch, caplog):
    def offline_list_repo_files(*args, **kwargs):
        raise huggingface_hub.errors.OfflineModeIsEnabled("offline")

    monkeypatch.setattr(
        garak.probes.fileformats.huggingface_hub,
        "list_repo_files",
        offline_list_repo_files,
    )

    p = garak.probes.fileformats.HF_Files()
    assert p.probe(_local_hf_generator("namespace/model-name")) == []
    assert "offline mode is enabled" in caplog.text


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
