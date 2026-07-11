# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import tempfile

import pytest

from garak import _plugins, _config

import garak.buffs.base
import garak.harnesses.base

HARNESSES = [
    classname for (classname, active) in _plugins.enumerate_plugins("harnesses")
]


@pytest.fixture(autouse=True)
def _config_loaded():
    """Load base config + a temp report file so harness.run() can write."""
    _config.load_base_config()
    _config.plugins.probes["test"]["generations"] = 1
    temp_report_file = tempfile.NamedTemporaryFile(
        mode="w+", suffix=".report.jsonl", delete=False
    )
    _config.transient.report_filename = temp_report_file.name
    _config.transient.reportfile = open(
        _config.transient.report_filename, "w", buffering=1, encoding="utf-8"
    )

    yield


@pytest.mark.parametrize("classname", HARNESSES)
def test_harness_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # any parameter that has a default must be supported
    unsupported_defaults = []
    if c._supported_params is not None:
        if hasattr(c, "DEFAULT_PARAMS"):
            for k, _ in c.DEFAULT_PARAMS.items():
                if k not in c._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


def test_harness_modality_match():
    t = {"text"}
    ti = {"text", "image"}
    tv = {"text", "vision"}
    tvi = {"text", "vision", "image"}

    # probe, generator
    assert garak.harnesses.base._modality_match(t, t, True) is True
    assert garak.harnesses.base._modality_match(ti, ti, True) is True
    assert garak.harnesses.base._modality_match(t, tv, True) is False
    assert garak.harnesses.base._modality_match(ti, t, True) is False

    # when strict is false, generator must support all probe modalities, but can also support more
    assert garak.harnesses.base._modality_match(t, t, False) is True
    assert garak.harnesses.base._modality_match(ti, t, False) is False
    assert garak.harnesses.base._modality_match(t, tvi, False) is True
    assert garak.harnesses.base._modality_match(ti, tvi, False) is True
    assert garak.harnesses.base._modality_match(t, ti, False) is True


def test_harness_detector_progress_shows_probe_name(mocker, monkeypatch):
    """Detector progress bar must show which probe is being processed (#324)."""
    mocker.patch("garak.harnesses.base._initialize_runtime_services")

    captured_descriptions = []
    real_tqdm = garak.harnesses.base.tqdm.tqdm

    def capturing_tqdm(*args, **kwargs):
        bar = real_tqdm(*args, **kwargs)
        original_set_description = bar.set_description

        def set_description(desc, *a, **kw):
            captured_descriptions.append(desc)
            return original_set_description(desc, *a, **kw)

        bar.set_description = set_description
        return bar

    monkeypatch.setattr(garak.harnesses.base.tqdm, "tqdm", capturing_tqdm)

    harness = garak.harnesses.base.Harness()
    model = _plugins.load_plugin("generators.test.Blank")
    probe = _plugins.load_plugin("probes.test.Blank")
    detector = _plugins.load_plugin("detectors.always.Pass")
    monkeypatch.setattr(
        _config.buffmanager,
        "buffs",
        [garak.buffs.base.Buff()],
    )

    harness.run(model, [probe], [detector], mocker.Mock())

    assert captured_descriptions, "detector progress bar should have a description"
    assert any(
        "probes.test.Blank" in desc and "detectors.always.Pass" in desc
        for desc in captured_descriptions
    ), "detector progress description should include probe and detector names"
