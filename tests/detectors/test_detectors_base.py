# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import tempfile

import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base


def test_filedetector_nonexist():
    d = garak.detectors.base.FileDetector()
    a = Attempt(prompt=Message(text=""))
    a.outputs = [Message(f) for f in [None, "", "/non/existing/file"]]
    a.notes["format"] = d.valid_format
    # FileDetector now yields None for skipped outputs (missing/empty/non-file)
    # so that detector_results stays length-aligned with attempt.outputs. The
    # evaluator indexes outputs by position; previously these were silently
    # dropped via ``continue``, misattributing later results to the wrong
    # outputs.
    results = list(d.detect(a))
    assert len(results) == len(
        a.outputs
    ), "FileDetector should yield one result per output (None for skipped)"
    assert all(
        r is None for r in results
    ), "FileDetector should yield None for non-existing/empty files"


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
# FileDetector result/output alignment.
#
# FileDetector.detect() iterates attempt.outputs and yields a score per file.
# Previously it used ``continue`` to skip missing/empty/non-file outputs,
# which made detector_results SHORTER than attempt.outputs. Since the
# evaluator indexes attempt.outputs by position, this misattributed later
# detector scores to the wrong outputs (and silently dropped some). The fix
# yields None for skipped outputs to preserve alignment.
# ---------------------------------------------------------------------------


class _ConcreteFileDetector(garak.detectors.base.FileDetector):
    """Minimal concrete FileDetector for testing alignment."""

    valid_format = "local filename"

    def _test_file(self, filename):
        return 1.0 if filename.endswith(".pkl") else 0.0


def test_filedetector_yields_none_for_missing_file_preserving_alignment():
    """FIX: a missing file between two valid files must yield None (not be
    dropped), so the valid files' scores stay aligned with their outputs."""
    d = _ConcreteFileDetector()
    tmpdir = tempfile.mkdtemp()
    valid_pkl = os.path.join(tmpdir, "real.pkl")
    valid_txt = os.path.join(tmpdir, "real.txt")
    open(valid_pkl, "w").write("x")
    open(valid_txt, "w").write("x")

    attempt = Attempt(prompt=Message(text=""))
    attempt.notes["format"] = "local filename"
    attempt.outputs = [
        Message(valid_pkl),
        Message("/nonexistent/path"),
        Message(valid_txt),
    ]
    results = list(d.detect(attempt))
    assert len(results) == 3, "one result per output (None for missing file)"
    assert results == [1.0, None, 0.0]
    # the critical alignment: outputs[0] hits (pkl), outputs[2] misses (txt)
    assert results[0] == 1.0
    assert results[2] == 0.0


def test_filedetector_yields_none_for_empty_output():
    """FIX: empty/None outputs yield None rather than being dropped."""
    d = _ConcreteFileDetector()
    attempt = Attempt(prompt=Message(text=""))
    attempt.notes["format"] = "local filename"
    attempt.outputs = [Message(""), Message(None), Message("/missing")]
    results = list(d.detect(attempt))
    assert len(results) == 3
    assert all(r is None for r in results)


def test_filedetector_all_valid_outputs_scored():
    """SANITY: when all outputs are valid files, alignment and scoring work."""
    d = _ConcreteFileDetector()
    tmpdir = tempfile.mkdtemp()
    pkl = os.path.join(tmpdir, "a.pkl")
    txt = os.path.join(tmpdir, "b.txt")
    open(pkl, "w").write("x")
    open(txt, "w").write("x")
    attempt = Attempt(prompt=Message(text=""))
    attempt.notes["format"] = "local filename"
    attempt.outputs = [Message(pkl), Message(txt)]
    assert list(d.detect(attempt)) == [1.0, 0.0]
