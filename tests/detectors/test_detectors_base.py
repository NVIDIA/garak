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
# Unicode normalization (issue #1867)
#
# StringDetector matches by raw byte comparison after optional lower-casing.
# Without normalization, a toxic term that is semantically present but written
# with non-ASCII code points (fullwidth, zero-width-interrupted) scores clean.
# The `normalize` DEFAULT_PARAM opts into homoglyph-resistant matching.
# ---------------------------------------------------------------------------

# ASCII baseline used to build the evasion variants below.
_PHRASE = "test phrase"

# Evasion variants — each is visually/semantically the same phrase as
# _PHRASE but written with non-ASCII code points that NFKC or Cf-stripping
# collapses back to ASCII.
_FULLWIDTH = "ｔｅｓｔ ｐｈｒａｓｅ"  # all-fullwidth; NFKC collapses to ASCII
_ZWJ = "te\u200dst phrase"  # zero-width joiner mid-word; only Cf-strip removes
_ZWSP = "test phra\u200bse"  # zero-width space mid-word; only Cf-strip removes
_ZWNJ = "test phra\u200cse"  # zero-width non-joiner mid-word; only Cf-strip removes


@pytest.fixture
def normalize_detector_factory():
    """Return a callable that builds a StringDetector with a given normalize mode."""

    def _make(normalize, matchtype="str"):
        detector = garak.detectors.base.StringDetector([_PHRASE])
        detector.matchtype = matchtype
        detector.normalize = normalize
        return detector

    return _make


def test_stringdetector_normalize_default_is_none():
    """The default value of `normalize` must be None for backward compatibility."""
    detector = garak.detectors.base.StringDetector([_PHRASE])
    assert detector.normalize is None


def test_stringdetector_normalize_none_leaves_evasion_unevaded(
    normalize_detector_factory,
):
    """With normalize=None (default), fullwidth/zero-width evasion still bypasses.

    This pins today's behavior so existing reported scores and tests remain
    unchanged. The fix is opt-in.
    """
    detector = normalize_detector_factory(None)
    for variant in (_FULLWIDTH, _ZWJ, _ZWSP, _ZWNJ):
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(variant)]
        assert detector.detect(attempt) == [
            0.0
        ], f"normalize=None must not collapse {variant!r} (backward compatibility)"


def test_stringdetector_normalize_nfkc_collapses_fullwidth(normalize_detector_factory):
    """NFKC collapses fullwidth homoglyphs to ASCII so the detector hits."""
    detector = normalize_detector_factory("NFKC")
    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(_FULLWIDTH)]
    assert detector.detect(attempt) == [1.0]


def test_stringdetector_normalize_nfkc_does_not_strip_zero_width(
    normalize_detector_factory,
):
    """NFKC preserves zero-width format chars; this is a documented limitation.

    Operators who need to catch zero-width insertion attacks must opt into
    `NFKC+strip_format`.
    """
    detector = normalize_detector_factory("NFKC")
    for variant in (_ZWJ, _ZWSP, _ZWNJ):
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(variant)]
        assert detector.detect(attempt) == [
            0.0
        ], f"NFKC alone must not strip zero-width chars (use NFKC+strip_format): {variant!r}"


def test_stringdetector_normalize_nfkc_strip_format_catches_zero_width(
    normalize_detector_factory,
):
    """NFKC + Cf-strip removes zero-width joiners/spaces/non-joiners so the detector hits."""
    detector = normalize_detector_factory("NFKC+strip_format")
    for variant in (_FULLWIDTH, _ZWJ, _ZWSP, _ZWNJ):
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(variant)]
        assert detector.detect(attempt) == [
            1.0
        ], f"NFKC+strip_format must collapse {variant!r} to a hit"


def test_stringdetector_normalize_works_with_word_matchtype(normalize_detector_factory):
    """Normalization applies before word-boundary regex matching."""
    detector = normalize_detector_factory("NFKC+strip_format", matchtype="word")
    attempt = Attempt(prompt=Message(text=""))
    # ZWJ inside the word would break \b matching without stripping.
    attempt.outputs = [Message(f"prefix {_ZWJ} suffix")]
    assert detector.detect(attempt) == [1.0]


def test_stringdetector_normalize_works_with_startswith_matchtype(
    normalize_detector_factory,
):
    """Normalization applies before startswith matching."""
    detector = normalize_detector_factory("NFKC", matchtype="startswith")
    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(_FULLWIDTH + " tail")]
    assert detector.detect(attempt) == [1.0]


def test_stringdetector_normalize_preserves_ascii_baseline(normalize_detector_factory):
    """ASCII matches still hit under every normalize mode."""
    for mode in (None, "NFKC", "NFKC+strip_format"):
        detector = normalize_detector_factory(mode)
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(f"begin {_PHRASE} end")]
        assert detector.detect(attempt) == [
            1.0
        ], f"ASCII baseline must hit under normalize={mode!r}"


def test_stringdetector_normalize_preserves_no_match(normalize_detector_factory):
    """Benign text with no target phrase stays clean under every normalize mode."""
    benign = "a completely unrelated sentence about the weather"
    for mode in (None, "NFKC", "NFKC+strip_format"):
        detector = normalize_detector_factory(mode)
        attempt = Attempt(prompt=Message(text=""))
        attempt.outputs = [Message(benign)]
        assert detector.detect(attempt) == [
            0.0
        ], f"Benign text must stay clean under normalize={mode!r}"


def test_stringdetector_normalize_preserves_case_insensitivity(
    normalize_detector_factory,
):
    """Normalization composes with case-insensitive lower-casing."""
    detector = normalize_detector_factory("NFKC")
    detector.case_sensitive = False
    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(_FULLWIDTH.upper())]
    assert detector.detect(attempt) == [1.0]


def test_stringdetector_normalize_invalid_value_raises():
    """An unsupported normalize value must raise ValueError at init, not silently misbehave."""
    detector = garak.detectors.base.StringDetector([_PHRASE])
    detector.normalize = "INVALID"
    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(_PHRASE)]
    with pytest.raises(ValueError, match="normalize"):
        detector.detect(attempt)


def test_stringdetector_normalize_nfkc_ascii_sanity(normalize_detector_factory):
    """Sanity check: NFKC on already-ASCII text still hits (no regression on the helper)."""
    detector = normalize_detector_factory("NFKC")
    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message(_PHRASE)]
    assert detector.detect(attempt) == [1.0]
