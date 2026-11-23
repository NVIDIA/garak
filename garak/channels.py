# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The channel catalog: where payloads reach a target.

A channel is a third axis next to technique (probe) and intent
(``IntentService``). Each channel names one place an indirect prompt
injection payload can reach a target, with a trust level (``user``,
``system``, or ``data``) and a delivery mode:

- ``conversation``: the payload is part of the ``Conversation``. No
  infrastructure.
- ``patch``: the generator changes its own request.
- ``out_of_band``: an injector changes a data source. The generator does
  nothing.

The catalog is closed: code references the module constants, YAML accepts
their string values, and ``get()`` validates with the valid ids listed
on error. Patch kinds name the request changes a generator can apply;
``CHANNEL_PATCHES`` maps each channel to the patch kinds that can route
traffic through an injector occupying it.
"""

from dataclasses import dataclass

TRUST_USER = "user"
TRUST_SYSTEM = "system"
TRUST_DATA = "data"

DELIVERY_CONVERSATION = "conversation"
DELIVERY_PATCH = "patch"
DELIVERY_OUT_OF_BAND = "out_of_band"

# channel ids
USER_TURN = "user_turn"
SYSTEM_PROMPT = "system_prompt"
TOOL_RESULT = "tool_result"
WORKSPACE_FILE = "workspace_file"
RETRIEVAL_DOCUMENT = "retrieval_document"

# patch kinds
PATCH_SYSTEM_PROMPT = "system_prompt"
PATCH_MCP_SERVER = "mcp_server"


@dataclass(frozen=True)
class Channel:
    """One place an injection payload can reach a target."""

    id: str
    description: str
    trust: str
    delivery: str


CHANNELS = {
    channel.id: channel
    for channel in (
        Channel(
            id=USER_TURN,
            description="user turns of the conversation itself",
            trust=TRUST_USER,
            delivery=DELIVERY_CONVERSATION,
        ),
        Channel(
            id=SYSTEM_PROMPT,
            description="the target's system prompt",
            trust=TRUST_SYSTEM,
            delivery=DELIVERY_PATCH,
        ),
        Channel(
            id=TOOL_RESULT,
            description="results of the tools the target calls",
            trust=TRUST_DATA,
            delivery=DELIVERY_OUT_OF_BAND,
        ),
        Channel(
            id=WORKSPACE_FILE,
            description="files in the target's workspace",
            trust=TRUST_DATA,
            delivery=DELIVERY_OUT_OF_BAND,
        ),
        Channel(
            id=RETRIEVAL_DOCUMENT,
            description="documents the target retrieves",
            trust=TRUST_DATA,
            delivery=DELIVERY_OUT_OF_BAND,
        ),
    )
}

#: patch kinds that can route traffic through an injector occupying each
#: channel; conversation channels need none
CHANNEL_PATCHES = {
    USER_TURN: frozenset(),
    SYSTEM_PROMPT: frozenset({PATCH_SYSTEM_PROMPT}),
    TOOL_RESULT: frozenset({PATCH_MCP_SERVER}),
    WORKSPACE_FILE: frozenset(),
    RETRIEVAL_DOCUMENT: frozenset(),
}

PATCH_KINDS = frozenset({PATCH_SYSTEM_PROMPT, PATCH_MCP_SERVER})


def get(channel_id: str) -> Channel:
    """Return the channel for one id, listing the valid ids on error."""
    try:
        return CHANNELS[channel_id]
    except KeyError:
        raise ValueError(
            f"unknown channel {channel_id!r}; valid channels are " f"{sorted(CHANNELS)}"
        ) from None


def channel_patches(channel_id: str) -> frozenset[str]:
    """Return the patch kinds that can route through one channel."""
    return frozenset(CHANNEL_PATCHES.get(get(channel_id).id, ()))


def get_patch(patch_kind: str) -> str:
    """Validate one patch kind, listing the valid kinds on error."""
    if patch_kind not in PATCH_KINDS:
        raise ValueError(
            f"unknown patch kind {patch_kind!r}; valid patch kinds are "
            f"{sorted(PATCH_KINDS)}"
        )
    return patch_kind
