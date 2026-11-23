# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.smuggling import smuggle_ascii


def test_encode_unicode_tags_maps_ascii_codepoints():
    encoded = smuggle_ascii.encode_unicode_tags("Abc 123!?")
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
    encoded = smuggle_ascii.tag_char_smuggling("Ab", desired_emoji="😈")
    assert (
        encoded == "😈\U000e0041\U000e0062"
    ), "tag character smuggling must prefix the encoded payload with its emoji"
