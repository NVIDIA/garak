# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pathlib

import pytest

import garak._plugins
import garak.attempt

PROBE_NAMES = (
    "probes.image_scaling.Bicubic",
    "probes.image_scaling.Bilinear",
    "probes.image_scaling.Nearest",
)


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_probe_loads(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    assert isinstance(probe.prompts, list)
    assert len(probe.prompts) > 0


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_prompts_are_messages(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    for p in probe.prompts:
        assert isinstance(p, garak.attempt.Message)


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_prompts_have_image_paths(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    for p in probe.prompts:
        assert p.data_path is not None
        assert pathlib.Path(p.data_path).exists(), (
            f"image file must exist: {p.data_path}"
        )


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_modality_includes_image(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    assert "image" in probe.modality.get("in", set())


def test_bicubic_is_active():
    assert garak._plugins.load_plugin("probes.image_scaling.Bicubic").active is True


def test_bilinear_and_nearest_are_inactive():
    assert garak._plugins.load_plugin("probes.image_scaling.Bilinear").active is False
    assert garak._plugins.load_plugin("probes.image_scaling.Nearest").active is False


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_each_probe_uses_three_images(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    assert len(probe.prompts) == 3


def test_bicubic_uses_bicubic_images():
    bicubic = garak._plugins.load_plugin("probes.image_scaling.Bicubic")
    image_names = [pathlib.Path(p.data_path).name for p in bicubic.prompts]
    assert all(name.startswith("bicubic_hb_") for name in image_names)


def test_bilinear_uses_bilinear_images():
    bilinear = garak._plugins.load_plugin("probes.image_scaling.Bilinear")
    image_names = [pathlib.Path(p.data_path).name for p in bilinear.prompts]
    assert all(name.startswith("bilinear_hb_") for name in image_names)


def test_nearest_uses_knn_images():
    nearest = garak._plugins.load_plugin("probes.image_scaling.Nearest")
    image_names = [pathlib.Path(p.data_path).name for p in nearest.prompts]
    assert all(name.startswith("nearest_hb_") for name in image_names)


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_primary_detector_set(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    assert probe.primary_detector == "mitigation.MitigationBypass"
