# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import pytest

from garak.resources.encodings import (
    base65536_encode,
    base65536_decode,
    hexagram_encode,
    hexagram_decode,
)

ROUNDTRIP_PAYLOADS = [
    b"",
    b"a",
    b"ab",
    b"abc",
    b"Hello, World!",
    "héllo \U0001f600".encode("utf-8"),
    bytes(range(256)),
    os.urandom(64),
]


@pytest.mark.parametrize("payload", ROUNDTRIP_PAYLOADS)
def test_base65536_roundtrip(payload):
    encoded = base65536_encode(payload)
    assert (
        base65536_decode(encoded) == payload
    ), "base65536 decode must invert encode for all byte inputs"


def test_base65536_known_vector():
    # Regression vector matching the reference qntm/base65536 implementation.
    assert (
        base65536_encode(bytes([0, 1, 2, 255, 254])) == "㔀𨔂ᗾ"
    ), "base65536 output must match the reference encoding"


@pytest.mark.parametrize("payload", ROUNDTRIP_PAYLOADS)
def test_hexagram_roundtrip(payload):
    encoded = hexagram_encode(payload)
    assert (
        hexagram_decode(encoded) == payload
    ), "hexagram decode must invert encode for all byte inputs"


def test_hexagram_known_vector():
    # Example from the reference ferno/hexagram-encode README.
    assert (
        hexagram_encode(bytes([0x00, 0x55, 0xFF])) == "䷁䷣䷄䷀"
    ), "hexagram output must match the reference encoding"


def test_hexagram_decode_rejects_invalid_input():
    with pytest.raises(ValueError):
        hexagram_decode("not hexagrams")


def test_base65536_decode_rejects_invalid_input():
    with pytest.raises(ValueError):
        base65536_decode("!not base65536!")
