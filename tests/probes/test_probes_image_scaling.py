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


def test_bicubic_and_bilinear_are_active():
    assert garak._plugins.load_plugin("probes.image_scaling.Bicubic").active is True
    assert garak._plugins.load_plugin("probes.image_scaling.Bilinear").active is True


def test_nearest_are_inactive():
    assert garak._plugins.load_plugin("probes.image_scaling.Nearest").active is False


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_each_probe_uses_three_images(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    assert len(probe.prompts) == 3


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_generated_images_are_png(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    for p in probe.prompts:
        assert p.data_path.endswith(".png")


@pytest.mark.parametrize("probe_name", PROBE_NAMES)
def test_primary_detector_set(probe_name):
    probe = garak._plugins.load_plugin(probe_name)
    assert probe.primary_detector == "image_scaling.ImageScalingCompliance"
