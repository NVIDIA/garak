# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the channel catalog."""

import pytest

import garak.channels as channels
from garak.channels import CHANNEL_PATCHES, CHANNELS, PATCH_KINDS, get, get_patch


@pytest.mark.parametrize("channel_id", sorted(CHANNELS))
def test_every_channel_in_the_catalog_is_valid(channel_id):
    channel = get(channel_id)
    assert channel.id == channel_id, "the catalog key must match the channel id"
    assert channel.description, "every channel must carry a description"
    assert channel.trust in (
        channels.TRUST_USER,
        channels.TRUST_SYSTEM,
        channels.TRUST_DATA,
    ), "every channel must name a known trust level"
    assert channel.delivery in (
        channels.DELIVERY_CONVERSATION,
        channels.DELIVERY_PATCH,
        channels.DELIVERY_OUT_OF_BAND,
    ), "every channel must name a known delivery mode"


@pytest.mark.parametrize("patch_kind", sorted(PATCH_KINDS))
def test_every_patch_kind_is_valid(patch_kind):
    assert get_patch(patch_kind) == patch_kind


@pytest.mark.parametrize("channel_id", sorted(CHANNELS))
def test_every_channel_patch_exists(channel_id):
    for patch_kind in CHANNEL_PATCHES[channel_id]:
        assert (
            patch_kind in PATCH_KINDS
        ), f"channel {channel_id} routes through unknown patch {patch_kind!r}"


def test_patch_delivery_channels_name_their_patch():
    """A patch-delivery channel routes through a patch of the same name."""
    for channel in CHANNELS.values():
        if channel.delivery == channels.DELIVERY_PATCH:
            assert (
                channel.id in CHANNEL_PATCHES[channel.id]
            ), f"{channel.id} delivers by patch but names no routing patch"


@pytest.mark.parametrize("bad", ["tool_results", "system", "mcp", ""])
def test_get_lists_the_valid_ids_on_error(bad):
    with pytest.raises(ValueError, match="valid channels are"):
        get(bad)


def test_get_patch_lists_the_valid_kinds_on_error():
    with pytest.raises(ValueError, match="valid patch kinds are"):
        get_patch("tool_result")


def test_channel_patches_rejects_unknown_channels():
    with pytest.raises(ValueError, match="valid channels are"):
        channels.channel_patches("tool_results")


def test_constants_match_the_catalog():
    assert channels.USER_TURN in CHANNELS
    assert channels.SYSTEM_PROMPT in CHANNELS
    assert channels.TOOL_RESULT in CHANNELS
    assert channels.WORKSPACE_FILE in CHANNELS
    assert channels.RETRIEVAL_DOCUMENT in CHANNELS


def test_list_channels_prints_the_catalog(capsys):
    from garak import command

    command.print_channels()

    out = capsys.readouterr().out
    for channel_id in sorted(CHANNELS):
        assert channel_id in out, "every channel must be listed"
    assert "injectors.mimcp.MiMCPInjector" in out, "tool_result lists its injector"
    assert "injectors.prompt.SystemPrompt" in out, "system_prompt lists its injector"
    assert (
        "probes.midojo.MidojoProbe" in out
    ), "the scenario-driven probe supports every channel"
    assert "mcp_server patch generators" in out, "routing patches list generators"
