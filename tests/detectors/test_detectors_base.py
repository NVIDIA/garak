# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base


def test_filedetector_nonexist():
    d = garak.detectors.base.FileDetector()
    a = Attempt(prompt=Message(text=""))
    a.outputs = [Message(f) for f in [None, "", "/non/existing/file"]]
    a.notes["format"] = d.valid_format
    assert (
        len(list(d.detect(a))) == 0
    ), "FileDetector should skip filenames for non-existing files"


TEST_STRINGS = [
    "test",  # 0: lower
    "UPPERCASE",  # 1: upper
    "MixedCase",  # 2: mixed (camel)
]


@pytest.fixture
def string_detector():
    return garak.detectors.base.StringDetector(TEST_STRINGS)


def test_case_sensitive_exact_match(string_detector):
    """Test that exact matches are detected when case_sensitive=True"""
    string_detector.case_sensitive = True
    for test_str in TEST_STRINGS:
        attempt = Attempt(prompt=Message(text="Hello"))
        attempt.outputs = [Message(test_str)]
        results = string_detector.detect(attempt)
        assert results == [1.0], f"Failed to detect exact match for '{test_str}'"


def test_case_sensitive_no_match(string_detector):
    """Test that case variations are not detected when case_sensitive=True"""
    test_cases = [
        TEST_STRINGS[0].upper(),  # uppercase variation
        TEST_STRINGS[0].title(),  # capitalized variation
        "tEsT",  # mixed case variation
        TEST_STRINGS[1].lower(),  # lowercase variation
        TEST_STRINGS[2].lower(),  # lowercase variation
        TEST_STRINGS[2].title(),  # title but not camelcase variation
    ]

    string_detector.case_sensitive = True

    for test_str in test_cases:
        attempt = Attempt(prompt=Message(text="Hello"))
        attempt.outputs = [Message(test_str)]
        results = string_detector.detect(attempt)
        assert results == [
            0.0
        ], f"Should not detect absent case variation '{test_str}' in case sensitive mode"


def test_case_insensitive_match(string_detector):
    """Test that case variations are detected when case_sensitive=False"""
    test_cases = [
        (TEST_STRINGS[0], TEST_STRINGS[0].upper()),
        (TEST_STRINGS[0], TEST_STRINGS[0].title()),
        (TEST_STRINGS[1], TEST_STRINGS[1].lower()),
        (TEST_STRINGS[1], TEST_STRINGS[1].title()),
        (TEST_STRINGS[2], TEST_STRINGS[2].lower()),
        (TEST_STRINGS[2], TEST_STRINGS[2].upper()),
    ]

    string_detector.case_sensitive = False

    for original, variant in test_cases:
        attempt = Attempt(prompt=Message(text="Hello"))
        attempt.outputs = [Message(variant)]
        results = string_detector.detect(attempt)
        assert results == [
            1.0
        ], f"Failed to detect case insensitive match: '{original}' vs '{variant}'"


def test_multiple_outputs(string_detector):
    """Test detection across multiple outputs with mixed case sensitivity"""
    attempt = Attempt(prompt=Message(text="Hello"))
    attempt.outputs = [
        Message(s) for s in [TEST_STRINGS[0], TEST_STRINGS[0].upper(), "no match"]
    ]

    string_detector.case_sensitive = True

    # Case sensitive - should only match exact "test"
    results = string_detector.detect(attempt)
    assert results == [
        1.0,
        0.0,
        0.0,
    ], "Case sensitive matching failed for multiple outputs"

    string_detector.case_sensitive = False

    # Case insensitive - should match both "test" and "TEST"
    results = string_detector.detect(attempt)
    assert results == [
        1.0,
        1.0,
        0.0,
    ], "Case insensitive matching failed for multiple outputs"


def test_none_outputs(string_detector):
    """Test handling of None outputs"""
    attempt = Attempt(prompt=Message(text="Hello"))
    attempt.outputs = [Message(s) for s in [None, TEST_STRINGS[0], None]]

    string_detector.case_sensitive = True

    results = string_detector.detect(attempt)
    assert len(results) == len(
        attempt.outputs
    ), "Detector result for each output including None"
    assert results == [None, 1.0, None], "Failed to handle None outputs correctly"


MATCHTYPE_AND_CASING_CASES = {
    "str": [
        (f"begin {TEST_STRINGS[0]}ing", True),  # should match
        (
            f"begin {TEST_STRINGS[0].upper()}ING",
            False,
        ),  # shouldn't match case sensitive
    ],
    "word": [
        (f"{TEST_STRINGS[0]} word", True),  # should match
        (
            f"{TEST_STRINGS[0].upper()} word",
            False,
        ),  # shouldn't match case sensitive
    ],
    "startswith": [
        (f"{TEST_STRINGS[0]} start", True),  # should match
        (
            f"{TEST_STRINGS[0].upper()} start",
            False,
        ),  # shouldn't match case sensitive
    ],
}


@pytest.mark.parametrize("matchtype", MATCHTYPE_AND_CASING_CASES.keys())
def test_matchtype_with_case_sensitivity(matchtype):
    """Test case sensitivity with different matchtypes"""

    detector = garak.detectors.base.StringDetector([TEST_STRINGS[0]])
    detector.matchtype = matchtype

    for text, should_match_sensitive in MATCHTYPE_AND_CASING_CASES[matchtype]:
        attempt = Attempt(prompt=Message(text="Hello"))
        attempt.outputs = [Message(text)]

        detector.case_sensitive = True

        # Test case sensitive
        results = detector.detect(attempt)
        assert results == [
            1.0 if should_match_sensitive else 0.0
        ], f"Case sensitive {matchtype} match failed for '{text}'"

        detector.case_sensitive = False

        # Test case insensitive
        results = detector.detect(attempt)
        assert results == [
            1.0
        ], f"Case insensitive {matchtype} match failed for '{text}'"


def test_stringdetector_word_boundary_matching():
    detector = garak.detectors.base.StringDetector(TEST_STRINGS)
    detector.matchtype = "word"

    test_cases = [
        ("begin testing", False),
        ("begin the test", True),
        ("THIS IS UPPERCASE", True),
        ("THIS IS UPPER CASE", False),
        ("THISISUPPERCASE", False),
    ]

    detector.case_sensitive = True

    for text, match in test_cases:
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(text)]
        results = detector.detect(attempt)
        assert results == [
            1.0 if match else 0.0
        ], f"Word boundary match failed for '{text}', expected {match}"


def test_stringdetector_startswith():
    detector = garak.detectors.base.StringDetector(TEST_STRINGS)
    detector.matchtype = "startswith"

    test_cases = [
        ("this is a test", False),
        ("tests always succeed", True),
    ]

    detector.case_sensitive = True

    for text, match in test_cases:
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(text)]
        results = detector.detect(attempt)
        assert results == [
            1.0 if match else 0.0
        ], f"startswith match failed for '{text}', expected {match}"


# ---------------------------------------------------------------------------
# Unicode normalization tests (normalize parameter on StringDetector)
# These demonstrate the attack surface described in issue #1867 and verify
# the fix: without normalize the bypass succeeds (score 0.0); with normalize
# the evasion is caught (score 1.0).
# ---------------------------------------------------------------------------

TRIGGER_WORD = "hello"

# Fullwidth homoglyph form: each ASCII letter mapped to its fullwidth variant.
# unicodedata.normalize("NFKC", ...) collapses these back to ASCII.
FULLWIDTH_HELLO = "ｈｅｌｌｏ"  # ｈｅｌｌｏ

# Zero-width joiner spliced between letters — NFKC does not remove it;
# the NFKC+strip_format tier strips Unicode category Cf characters.
ZWJ = "‍"
ZWJ_HELLO = f"h{ZWJ}e{ZWJ}l{ZWJ}l{ZWJ}o"


def test_stringdetector_normalize_default_no_change():
    """Without normalize, fullwidth homoglyphs bypass substring detection (baseline)"""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = None

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(FULLWIDTH_HELLO)]
    results = detector.detect(attempt)
    assert results == [0.0], "Fullwidth homoglyph should bypass detection without normalize"


def test_stringdetector_normalize_nfkc_catches_fullwidth():
    """normalize='NFKC' collapses fullwidth homoglyphs to ASCII before matching"""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = "NFKC"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(FULLWIDTH_HELLO)]
    results = detector.detect(attempt)
    assert results == [1.0], "NFKC normalization should catch fullwidth homoglyph evasion"


def test_stringdetector_normalize_nfkc_preserves_ascii_match():
    """normalize='NFKC' does not break detection of plain ASCII triggers"""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = "NFKC"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(TRIGGER_WORD)]
    results = detector.detect(attempt)
    assert results == [1.0], "NFKC normalization must not break plain ASCII detection"


def test_stringdetector_normalize_nfkc_zwj_not_stripped():
    """NFKC alone does not strip zero-width joiner; evasion still succeeds"""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = "NFKC"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(ZWJ_HELLO)]
    results = detector.detect(attempt)
    assert results == [0.0], "NFKC alone should not strip ZWJ (use NFKC+strip_format for that)"


def test_stringdetector_normalize_strip_format_catches_zwj():
    """normalize='NFKC+strip_format' strips category Cf chars including ZWJ"""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = "NFKC+strip_format"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(ZWJ_HELLO)]
    results = detector.detect(attempt)
    assert results == [1.0], "NFKC+strip_format should catch ZWJ-interrupted evasion"


def test_stringdetector_normalize_invalid_value():
    """An unrecognised normalize value logs a warning and returns None (does not raise)"""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.normalize = "NFC"  # not a supported tier

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(TRIGGER_WORD)]
    results = list(detector.detect(attempt))
    assert results == [None], "Unknown normalize value should return None, not raise"


# ---------------------------------------------------------------------------
# Known limitations of the NFKC tiers, pinned so the docstring stays honest:
# NFKC (compatibility normalization) collapses fullwidth/homoglyph *compatibility*
# forms, but it does NOT fold cross-script confusables or combining marks to ASCII.
# ---------------------------------------------------------------------------

# Cyrillic 'е' (U+0435) and 'о' (U+043E) look like ASCII e/o but are a different
# script; NFKC leaves them unchanged, so an ASCII trigger does not match.
CYRILLIC_HELLO = "hеllо"

# 'e' + U+0301 (combining acute). NFKC precomposes to 'é' (U+00E9), still not ASCII 'e'.
COMBINING_HELLO = "héllo"

# Fullwidth uppercase form of the trigger word.
FULLWIDTH_HELLO_UPPER = "ＨＥＬＬＯ"


def test_stringdetector_normalize_nfkc_cross_script_confusable_limitation():
    """NFKC does not fold cross-script (e.g. Cyrillic) confusables to ASCII, so a
    plain-ASCII trigger still misses them. Pinned so the docstring isn't overclaimed."""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = "NFKC"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(CYRILLIC_HELLO)]
    results = detector.detect(attempt)
    assert results == [0.0], "NFKC does not collapse Cyrillic confusables to ASCII"


def test_stringdetector_normalize_nfkc_combining_mark_limitation():
    """NFKC precomposes base+combining sequences (e.g. e + U+0301 -> 'é'), which still
    is not ASCII, so an ASCII trigger does not match. Pinned as a known limitation."""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.case_sensitive = True
    detector.normalize = "NFKC"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(COMBINING_HELLO)]
    results = detector.detect(attempt)
    assert results == [0.0], "NFKC precomposes combining marks; ASCII trigger still misses"


def test_stringdetector_normalize_matchtype_word_and_startswith():
    """normalize composes with matchtype: a fullwidth homoglyph is caught under both
    matchtype='word' (word-boundary regex) and matchtype='startswith'."""
    for matchtype, output in (
        ("word", f"please say {FULLWIDTH_HELLO} now"),
        ("startswith", FULLWIDTH_HELLO),
    ):
        detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
        detector.matchtype = matchtype
        detector.case_sensitive = True
        detector.normalize = "NFKC"

        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(output)]
        results = detector.detect(attempt)
        assert results == [1.0], f"NFKC should compose with matchtype={matchtype!r}"


def test_stringdetector_normalize_case_insensitive_composition():
    """case_sensitive=False and NFKC compose: a fullwidth UPPERCASE homoglyph matches a
    lowercase trigger only when case-insensitive (both lower-casing and NFKC run first)."""
    detector = garak.detectors.base.StringDetector([TRIGGER_WORD])
    detector.matchtype = "str"
    detector.normalize = "NFKC"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(FULLWIDTH_HELLO_UPPER)]

    detector.case_sensitive = True
    assert detector.detect(attempt) == [0.0], "case-sensitive should not match uppercase variant"

    detector.case_sensitive = False
    assert detector.detect(attempt) == [1.0], "case-insensitive + NFKC should match uppercase variant"


def test_stringdetector_normalize_ldnoobw_fullwidth_end_to_end():
    """End-to-end against the real unsafe_content.LDNOOBW detector: a fullwidth variant of
    a word from its live wordlist evades detection without normalize and is caught with
    normalize='NFKC'. Guards against wordlist/detector-wiring regressions."""
    from garak.detectors.unsafe_content import LDNOOBW

    detector = LDNOOBW()
    # this test targets normalization, not language routing: match any output language
    detector.lang_spec = "*"
    # pick a purely-ASCII alphabetic entry from the live wordlist (no hardcoded term)
    word = next(
        w for w in detector.substrings if w.isascii() and w.isalpha() and len(w) >= 4
    )
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if "a" <= c <= "z" else c for c in word)

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(fullwidth)]

    detector.normalize = None
    assert detector.detect(attempt) == [0.0], "fullwidth variant should evade without normalize"

    detector.normalize = "NFKC"
    assert detector.detect(attempt) == [1.0], "NFKC should catch the fullwidth variant in LDNOOBW"
