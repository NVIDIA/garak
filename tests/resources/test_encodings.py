# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.resources.encodings import leetspeak, morse


@pytest.mark.parametrize(
    "transmute_chance, expected",
    [(0.0, "ieaostIEAOST"), (1.0, "134057134057")],
)
def test_leetspeak_transmute_chance(transmute_chance, expected):
    assert leetspeak("ieaostIEAOST", transmute_chance=transmute_chance) == expected


def test_leetspeak_leaves_unswappable_characters_unchanged():
    assert leetspeak("xyz", transmute_chance=1.0) == "xyz"


@pytest.mark.parametrize(
    "text, expected",
    [
        # decodes as "A.B?C", not the "ABC" it used to collapse to
        (b"a.b?c", b".- .-.-.- -... ..--.. -.-."),
        (b"Don't panic!", b"-.. --- -. .----. - / .--. .- -. .. -.-. -.-.--"),
        (b"email: x@y", b". -- .- .. .-.. ---... / -..- .--.-. -.--"),
    ],
)
def test_morse_preserves_itu_punctuation(text, expected):
    assert morse(text) == expected


@pytest.mark.parametrize(
    "char, code",
    [
        (".", ".-.-.-"),
        (",", "--..--"),
        ("?", "..--.."),
        ("'", ".----."),
        ("!", "-.-.--"),
        ("/", "-..-."),
        ("(", "-.--."),
        (")", "-.--.-"),
        ("&", ".-..."),
        (":", "---..."),
        (";", "-.-.-."),
        ("=", "-...-"),
        ("+", ".-.-."),
        ("-", "-....-"),
        ("_", "..--.-"),
        ('"', ".-..-."),
        ("$", "...-..-"),
        ("@", ".--.-."),
    ],
)
def test_morse_itu_punctuation_table(char, code):
    assert morse(char.encode()) == code.encode()


def test_morse_still_drops_characters_without_a_code():
    assert morse(b"a#b") == b".- -..."
