# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Capability names shared by generators and injectors.

A capability names an interaction surface a target draws untrusted content
from, for example ``mcp`` for a target that queries external MCP servers.
Generators advertise capabilities through ``Generator.list_capabilities``;
injectors declare the capabilities they can occupy.

The vocabulary is closed: every capability is a ``Capability`` member, so
generators and injectors reference the same names without typos. Generators
own the mapping from their target's tool types onto these members; tool
types they cannot map carry no capability and are dropped. Supporting a new
surface starts with adding a member here.
"""

from enum import StrEnum


class Capability(StrEnum):
    """Capability names for target interaction surfaces.

    Members are strings, so raw names from external tool manifests
    interoperate directly: ``Capability.MCP in {"mcp"}`` holds.
    """

    MCP = "mcp"
    FILE = "file"
    WEB_SEARCH = "web_search"
    CODE = "code"
    SHELL = "shell"
