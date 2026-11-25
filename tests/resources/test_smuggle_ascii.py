# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.smuggling.smuggle_ascii import (
    sneaky_bits_smuggling,
    variant_smuggling,
    encode_unicode_tags,
    tag_char_smuggling,
)

ZERO, ONE = chr(0x2062), chr(0x2064)


def test_encode_unicode_tags_maps_ascii_codepoints():
    encoded = encode_unicode_tags("Abc 123!?")
    assert [ord(character) for character in encoded] == [
        0xE0041,
        0xE0062,
        0xE0063,
        0xE0020,
        0xE0031,
        0xE0032,
        0xE0033,
        0xE0021,
        0xE003F,
    ], "each ASCII character must map to its Unicode Tag counterpart"


def test_tag_char_smuggling_prefixes_encoded_payload_with_emoji():
    encoded = tag_char_smuggling("Ab", desired_emoji="😈")
    assert (
        encoded == "😈\U000e0041\U000e0062"
    ), "tag character smuggling must prefix the encoded payload with its emoji"


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


def test_sneaky_bits_encodes_spaces_as_zero_width_space():
    a_bits = ZERO + ONE + ZERO + ZERO + ZERO + ZERO + ZERO + ONE
    assert sneaky_bits_smuggling(" ") == chr(
        0x200B
    ), "a space should be encoded as a zero-width space"
    assert (
        sneaky_bits_smuggling("A A") == a_bits + chr(0x200B) + a_bits
    ), "spaces between characters should be encoded as zero-width spaces"


def test_sneaky_bits_round_trip():
    payload = "Trust No AI - 42 café"
    assert (
        _sneaky_bits_decode(sneaky_bits_smuggling(payload)) == payload
    ), "encoded payload should decode back to the original text"


def _variant_selector_decode(encoded: str) -> str:
    decoded = []
    for ch in encoded:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            decoded.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            decoded.append(cp - 0xE0100 + 16)
        else:
            raise AssertionError(f"U+{cp:04X} is not a variation selector")
    return bytes(decoded).decode("utf-8")


def test_variant_smuggling_reference_mapping():
    assert variant_smuggling("A") == chr(
        0xE0131
    ), "bytes from 16 up should map to U+E0100 + (byte - 16)"
    assert variant_smuggling("\t") == chr(
        0xFE09
    ), "bytes below 16 should map to U+FE00 + byte"


def test_variant_smuggling_round_trip():
    payload = "Hello\tcafé €"
    assert (
        _variant_selector_decode(variant_smuggling(payload)) == payload
    ), "encoded payload should decode back to the original text"
