# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import pytest

import garak._plugins
import garak.attempt
import garak.probes.image_anamorpher


ANAMORPH_NAMES = (
    "probes.image_anamorpher.Anamorpher",
    "probes.image_anamorpher.AnamorphTiny",
)


@pytest.mark.parametrize("plugin_name", ANAMORPH_NAMES)
def test_anamorpher_load(plugin_name):
    plugin = garak._plugins.load_plugin(plugin_name)
    assert isinstance(
        plugin.prompts, list
    ), "anamorpher prompts should be a list"
    assert len(plugin.prompts) > 0, "anamorpher should have at least one prompt"
    assert isinstance(
        plugin.prompts[0], garak.attempt.Message
    ), "anamorpher prompts should be Messages"


@pytest.mark.parametrize("plugin_name", ANAMORPH_NAMES)
def test_anamorpher_attaches_image(plugin_name):
    plugin = garak._plugins.load_plugin(plugin_name)
    for prompt in plugin.prompts:
        assert (
            prompt.data_path is not None
        ), "anamorpher prompt should carry an image data path"
        assert os.path.isfile(
            prompt.data_path
        ), f"anamorpher image file should exist on disk: {prompt.data_path}"
        # PNG magic number
        with open(prompt.data_path, "rb") as f:
            head = f.read(8)
        assert head[:8] == b"\x89PNG\r\n\x1a\n", "anamorpher image should be a PNG"


def test_prompt_counts():
    full = garak._plugins.load_plugin("probes.image_anamorpher.Anamorpher")
    tiny = garak._plugins.load_plugin("probes.image_anamorpher.AnamorphTiny")
    assert len(full.prompts) > len(
        tiny.prompts
    ), "AnamorphTiny should have fewer prompts than Anamorpher"


@pytest.mark.parametrize("plugin_name", ANAMORPH_NAMES)
def test_anamorpher_modality(plugin_name):
    plugin = garak._plugins.load_plugin(plugin_name)
    assert plugin.modality == {"in": {"text", "image"}}


def test_anamorpher_image_dimensions():
    """Generated images should be at full_size resolution, not downsample_size."""
    from PIL import Image

    plugin = garak._plugins.load_plugin("probes.image_anamorpher.AnamorphTiny")
    img = Image.open(plugin.prompts[0].data_path)
    assert img.size == (
        plugin.full_size,
        plugin.full_size,
    ), f"image should be ({plugin.full_size}, {plugin.full_size}); got {img.size}"
