# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared capability vocabulary."""

from garak.capabilities import Capability


def test_capability_members_equal_their_string_values():
    assert Capability.MCP == "mcp", "members must compare equal to plain strings"
    assert Capability.FILE == "file", "members must compare equal to plain strings"


def test_capability_membership_against_raw_names():
    raw = {"mcp", "web_search"}
    assert Capability.MCP in raw, "raw names from tool manifests must interoperate"


def test_capability_survives_serialisation():
    import json

    assert json.dumps(Capability.MCP) == '"mcp"', "members must serialise as strings"
