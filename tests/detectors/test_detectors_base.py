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
# Regex-metacharacter handling in word-match mode (re.escape fix).
#
# The word matchtype builds a regex via r"\b" + substring + r"\b". Substrings
# containing regex metacharacters (as real Surge profanity-list entries do --
# e.g. "c*nt", "bi+ch") must be escaped so they are matched literally, not
# compiled as regex. Without re.escape: "c*nt" matches the benign word "nt"
# (c* = zero-or-more c), and "(" or "[" crash the detector with re.error.
# ---------------------------------------------------------------------------

# Substrings that are invalid regexes and would crash without re.escape.
INVALID_REGEX_SUBSTRINGS = ["(result", "(", "[", "a{2,1}", "(*"]


@pytest.mark.parametrize("trigger", INVALID_REGEX_SUBSTRINGS)
def test_word_match_does_not_crash_on_invalid_regex(trigger):
    detector = garak.detectors.base.StringDetector([trigger])
    detector.matchtype = "word"
    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message("some benign model output")]
    results = detector.detect(attempt)
    assert results == [0.0], f"trigger {trigger!r} should be a non-matching literal"


def test_word_match_c_star_nt_does_not_match_benign_nt():
    """The Surge-list term 'c*nt' compiled as 'c*' (0+ c) + 'nt', so the word
    boundary regex matched the benign word 'nt'. After re.escape it matches
    only the literal 'c*nt'."""
    detector = garak.detectors.base.StringDetector(["c*nt"])
    detector.matchtype = "word"
    detector.case_sensitive = False

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message("nt"), Message("c*nt")]
    results = detector.detect(attempt)
    assert results == [0.0, 1.0], "c*nt should match only the literal, not 'nt'"


def test_word_match_bi_plus_ch_does_not_match_bich():
    """The Surge-list term 'bi+ch' compiled as 'bi+' (1+ i) + 'ch', matching
    'bich'/'biich'. After re.escape it matches only the literal 'bi+ch'."""
    detector = garak.detectors.base.StringDetector(["bi+ch"])
    detector.matchtype = "word"
    detector.case_sensitive = False

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message("bich"), Message("biich"), Message("bi+ch")]
    results = detector.detect(attempt)
    assert results == [0.0, 0.0, 1.0]


def test_word_match_s_o_b_dot_not_treated_as_any_char():
    """The Surge-list term 's.o.b.' compiled with '.' as any-char. After
    re.escape the dots are literal; 'sxobx' no longer matches. Note: under
    word-boundary semantics a term ending in a non-word char ('.') does not
    match its own literal either -- this is a pre-existing property of the
    word matchtype, not changed by re.escape. The key assertion is the
    false-positive 'sxobx' is no longer matched."""
    detector = garak.detectors.base.StringDetector(["s.o.b."])
    detector.matchtype = "word"
    detector.case_sensitive = False

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message("sxobx")]
    results = detector.detect(attempt)
    assert results == [0.0], "s.o.b. should not match 'sxobx' after escaping"


def test_word_match_plain_term_still_matches_after_escape():
    """Backward compatibility: a plain substring like 'secret' must still
    match under word mode after re.escape is applied."""
    detector = garak.detectors.base.StringDetector(["secret"])
    detector.matchtype = "word"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message("a secret message"), Message("nothing here")]
    results = detector.detect(attempt)
    assert results == [1.0, 0.0]


def test_str_matchtype_unaffected_by_escape():
    """The 'str' matchtype uses ``in`` (no regex) and is unaffected by the
    re.escape fix; confirm it still handles metachar substrings literally."""
    detector = garak.detectors.base.StringDetector(["c*nt"])
    detector.matchtype = "str"

    attempt = Attempt(prompt=Message(text=""))
    attempt.outputs = [Message("c*nt"), Message("cnt")]
    results = detector.detect(attempt)
    assert results == [1.0, 0.0]
