# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt
import garak.detectors.base


def test_filedetector_nonexist():
    d = garak.detectors.base.FileDetector()
    a = Attempt(prompt="")
    a.outputs = [None, "", "/non/existing/file"]
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
    for test_str in TEST_STRINGS:
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [test_str]
        results = string_detector.detect(attempt, case_sensitive=True)
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

    for test_str in test_cases:
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [test_str]
        results = string_detector.detect(attempt, case_sensitive=True)
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

    for original, variant in test_cases:
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [variant]
        results = string_detector.detect(attempt, case_sensitive=False)
        assert results == [
            1.0
        ], f"Failed to detect case insensitive match: '{original}' vs '{variant}'"


def test_multiple_outputs(string_detector):
    """Test detection across multiple outputs with mixed case sensitivity"""
    attempt = Attempt(prompt="Hello")
    attempt.outputs = [TEST_STRINGS[0], TEST_STRINGS[0].upper(), "no match"]

    # Case sensitive - should only match exact "test"
    results = string_detector.detect(attempt, case_sensitive=True)
    assert results == [
        1.0,
        0.0,
        0.0,
    ], "Case sensitive matching failed for multiple outputs"

    # Case insensitive - should match both "test" and "TEST"
    results = string_detector.detect(attempt, case_sensitive=False)
    assert results == [
        1.0,
        1.0,
        0.0,
    ], "Case insensitive matching failed for multiple outputs"


def test_none_outputs(string_detector):
    """Test handling of None outputs"""
    attempt = Attempt(prompt="Hello")
    attempt.outputs = [None, TEST_STRINGS[0], None]

    results = string_detector.detect(attempt, case_sensitive=True)
    assert len(results) == 1, "Detector expected to skip None outputs"
    assert results == [1.0], "Failed to handle None outputs correctly"


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
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [text]

        # Test case sensitive
        results = detector.detect(attempt, case_sensitive=True)
        assert results == [
            1.0 if should_match_sensitive else 0.0
        ], f"Case sensitive {matchtype} match failed for '{text}'"

        # Test case insensitive
        results = detector.detect(attempt, case_sensitive=False)
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

    for text, match in test_cases:
        attempt = Attempt(prompt="")
        attempt.outputs = [text]
        results = detector.detect(attempt, case_sensitive=True)
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

    for text, match in test_cases:
        attempt = Attempt(prompt="")
        attempt.outputs = [text]
        results = detector.detect(attempt, case_sensitive=True)
        assert results == [
            1.0 if match else 0.0
        ], f"startswith match failed for '{text}', expected {match}"
