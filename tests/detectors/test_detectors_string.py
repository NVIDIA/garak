# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt
from garak.detectors.base import StringDetector

TEST_STRINGS = [
    "test",
    "UPPERCASE",
    "MixedCase",
]

@pytest.fixture
def string_detector():
    return StringDetector(TEST_STRINGS)

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
        "TEST",  # uppercase variation
        "Test",  # capitalized variation
        "tEsT",  # mixed case variation
        "uppercase",  # lowercase variation
        "mixedcase",  # lowercase variation
    ]
    
    for test_str in test_cases:
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [test_str]
        results = string_detector.detect(attempt, case_sensitive=True)
        assert results == [0.0], f"Should not detect case variation '{test_str}' in case sensitive mode"

def test_case_insensitive_match(string_detector):
    """Test that case variations are detected when case_sensitive=False"""
    test_cases = [
        ("test", "TEST"),
        ("test", "Test"),
        ("UPPERCASE", "uppercase"),
        ("MixedCase", "mixedcase"),
        ("MixedCase", "MIXEDCASE"),
    ]
    
    for original, variant in test_cases:
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [variant]
        results = string_detector.detect(attempt, case_sensitive=False)
        assert results == [1.0], f"Failed to detect case insensitive match: '{original}' vs '{variant}'"

def test_multiple_outputs(string_detector):
    """Test detection across multiple outputs with mixed case sensitivity"""
    attempt = Attempt(prompt="Hello")
    attempt.outputs = ["test", "TEST", "no match"]
    
    # Case sensitive - should only match exact "test"
    results = string_detector.detect(attempt, case_sensitive=True)
    assert results == [1.0, 0.0, 0.0], "Case sensitive matching failed for multiple outputs"
    
    # Case insensitive - should match both "test" and "TEST"
    results = string_detector.detect(attempt, case_sensitive=False)
    assert results == [1.0, 1.0, 0.0], "Case insensitive matching failed for multiple outputs"

def test_none_outputs(string_detector):
    """Test handling of None outputs"""
    attempt = Attempt(prompt="Hello")
    attempt.outputs = [None, "test", None]
    
    results = string_detector.detect(attempt, case_sensitive=True)
    assert len(results) == 1, "Should skip None outputs"
    assert results == [1.0], "Failed to handle None outputs correctly"

@pytest.mark.parametrize("matchtype", ["str", "word", "startswith"])
def test_matchtype_with_case_sensitivity(matchtype):
    """Test case sensitivity with different matchtypes"""
    detector = StringDetector(["test"])
    detector.matchtype = matchtype
    
    test_cases = {
        "str": [
            ("begin testing", True),  # should match
            ("begin TESTING", False),  # shouldn't match case sensitive
        ],
        "word": [
            ("test word", True),  # should match
            ("TEST word", False),  # shouldn't match case sensitive
        ],
        "startswith": [
            ("test start", True),  # should match
            ("TEST start", False),  # shouldn't match case sensitive
        ],
    }
    
    for text, should_match_sensitive in test_cases[matchtype]:
        attempt = Attempt(prompt="Hello")
        attempt.outputs = [text]
        
        # Test case sensitive
        results = detector.detect(attempt, case_sensitive=True)
        assert results == [1.0 if should_match_sensitive else 0.0], \
            f"Case sensitive {matchtype} match failed for '{text}'"
        
        # Test case insensitive
        results = detector.detect(attempt, case_sensitive=False)
        assert results == [1.0], \
            f"Case insensitive {matchtype} match failed for '{text}'"
