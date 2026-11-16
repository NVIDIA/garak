# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.smuggling.smuggle_ascii import sneaky_bits_smuggling

ZERO, ONE = chr(0x2062), chr(0x2064)


def _sneaky_bits_decode(encoded: str) -> str:
    words = encoded.split(chr(0x200B))
    decoded = []
    for word in words:
        bits = word.replace(ZERO, "0").replace(ONE, "1")
        assert len(bits) % 8 == 0, "each encoded byte should be eight bits wide"
        decoded.append(
            bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)).decode(
                "utf-8"
            )
        )
    return " ".join(decoded)


def test_sneaky_bits_reference_example():
    assert sneaky_bits_smuggling("A") == (
        ZERO + ONE + ZERO + ZERO + ZERO + ZERO + ZERO + ONE
    ), "'A' should encode to the eight-bit example from the Sneaky Bits post"


def test_sneaky_bits_distinct_payloads_stay_distinct():
    assert sneaky_bits_smuggling("a!") != sneaky_bits_smuggling(
        "0a"
    ), "variable-width bit runs must not make different payloads collide"


def test_sneaky_bits_round_trip():
    payload = "Trust No AI - 42 café"
    assert (
        _sneaky_bits_decode(sneaky_bits_smuggling(payload)) == payload
    ), "encoded payload should decode back to the original text"
