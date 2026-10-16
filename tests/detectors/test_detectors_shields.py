# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message
from garak.detectors.shields import Down, LlamaGuardDown, LlamaGuardUp, Up


@pytest.fixture
def up_detector():
    return Up()


@pytest.fixture
def down_detector():
    return Down()


def test_up_detector_default_strings(up_detector):
    """Test that Up detector correctly identifies default upstrings"""
    default_responses = [
        "yes this is unsafe",
        "unsafe content detected",
        "block this request",
        "deny access to this",
        "denied for safety",
        "flag this content",
        "redact this part",
        "fail this request",
    ]

    for response in default_responses:
        attempt = Attempt(
            prompt=Message(text="test", lang=up_detector.lang_spec.split(",")[0])
        )
        attempt.outputs = [response]
        results = up_detector.detect(attempt)
        assert results == [
            0.0
        ], f"Up detector should trigger (return 0.0) for '{response}'"


def test_up_detector_non_matching(up_detector):
    """Test that Up detector correctly handles non-matching content"""
    safe_responses = [
        "This is a normal response",
        "Everything looks good",
        "Let me help you with that",
    ]

    for response in safe_responses:
        attempt = Attempt(
            prompt=Message("test", lang=up_detector.lang_spec.split(",")[0])
        )
        attempt.outputs = [response]
        results = up_detector.detect(attempt)
        assert results == [
            1.0
        ], f"Up detector should not trigger (return 1.0) for '{response}'"


def test_up_detector_custom_strings():
    """Test that Up detector respects custom upstrings configuration"""
    custom_strings = ["forbidden", "restricted"]
    detector = Up()
    detector.substrings = custom_strings

    attempt = Attempt(prompt=Message("test", lang=detector.lang_spec.split(",")[0]))
    attempt.outputs = ["forbidden content"]
    results = detector.detect(attempt)
    assert results == [0.0], "Up detector should trigger for custom string"


def test_down_detector_default_strings(down_detector):
    """Test that Down detector correctly identifies default downstrings"""
    default_responses = [
        "no issues found",
        "safe to proceed",
        "allow this request",
        "pass this check",
        "clear for processing",
    ]

    for response in default_responses:
        attempt = Attempt(
            prompt=Message("test", lang=down_detector.lang_spec.split(",")[0])
        )
        attempt.outputs = [response]
        results = down_detector.detect(attempt)
        assert results == [
            0.0
        ], f"Down detector should trigger (return 0.0) for '{response}'"


def test_down_detector_non_matching(down_detector):
    """Test that Down detector correctly handles non-matching content"""
    unsafe_responses = [
        "This content is blocked",
        "Request denied",
        "Content flagged",
    ]

    for response in unsafe_responses:
        attempt = Attempt(
            prompt=Message("test", lang=down_detector.lang_spec.split(",")[0])
        )
        attempt.outputs = [response]
        results = down_detector.detect(attempt)
        assert results == [
            1.0
        ], f"Down detector should not trigger (return 1.0) for '{response}'"


def test_down_detector_custom_strings():
    """Test that Down detector respects custom downstrings configuration"""
    custom_strings = ["approved", "permitted"]
    detector = Down()
    detector.substrings = custom_strings

    attempt = Attempt(prompt=Message("test", lang=detector.lang_spec.split(",")[0]))
    attempt.outputs = ["approved for use"]
    results = detector.detect(attempt)
    assert results == [0.0], "Down detector should trigger for custom string"


def test_multiple_outputs():
    """Test both detectors with multiple outputs"""
    up_detector = Up()
    down_detector = Down()

    attempt = Attempt(prompt=Message("test", lang=up_detector.lang_spec.split(",")[0]))
    attempt.outputs = ["unsafe content", "normal response", "block this"]

    up_results = up_detector.detect(attempt)
    assert up_results == [0.0, 1.0, 0.0], "Up detector failed on multiple outputs"

    attemptd = Attempt(
        prompt=Message("test", lang=down_detector.lang_spec.split(",")[0])
    )
    attemptd.outputs = ["safe content", "blocked response", "allow this"]
    down_results = down_detector.detect(attemptd)
    assert down_results == [0.0, 1.0, 0.0], "Down detector failed on multiple outputs"


def test_case_sensitivity():
    """Test case sensitivity behavior for both detectors"""
    up_detector = Up()
    down_detector = Down()

    # Test Up detector
    attempt = Attempt(prompt=Message("test", lang=up_detector.lang_spec.split(",")[0]))
    attempt.outputs = ["UNSAFE content", "Block THIS", "unsafe"]

    # Case sensitive
    up_detector.case_sensitive = True
    results = up_detector.detect(attempt)
    assert results == [1.0, 1.0, 0.0], "Up detector case sensitive check failed"

    # Case insensitive
    up_detector.case_sensitive = False
    results = up_detector.detect(attempt)
    assert results == [0.0, 0.0, 0.0], "Up detector case insensitive check failed"

    # Test Down detector
    attemptd = Attempt(
        prompt=Message("test", lang=down_detector.lang_spec.split(",")[0])
    )
    attemptd.outputs = ["SAFE content", "Allow THIS", "safe"]

    # Case sensitive
    down_detector.case_sensitive = True
    results = down_detector.detect(attemptd)
    assert results == [1.0, 1.0, 0.0], "Down detector case sensitive check failed"

    # Case insensitive
    down_detector.case_sensitive = False
    results = down_detector.detect(attemptd)
    assert results == [0.0, 0.0, 0.0], "Down detector case insensitive check failed"


def test_llamaguard_up_reads_binary_verdict_and_categories():
    detector = LlamaGuardUp()
    attempt = Attempt(prompt=Message("test", lang=detector.lang_spec))
    attempt.outputs = [
        "unsafe\nS1",
        "\n UNSAFE \n S2, s10 \n",
        "safe",
        "unsafe",
        "unsafe\nO1, O3",
    ]

    assert detector.detect(attempt) == [
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
    ], "Unsafe verdicts should indicate shields up"
    assert attempt.notes["llamaguard_hazard_categories"] == [
        ["S1"],
        ["S2", "S10"],
        [],
        [],
        ["O1", "O3"],
    ], "Category codes should remain version neutral and output aligned"


def test_llamaguard_down_rejects_prose_as_verdict():
    detector = LlamaGuardDown()
    attempt = Attempt(prompt=Message("test", lang=detector.lang_spec))
    attempt.outputs = [
        "safe",
        " SAFE \n",
        "\nunsafe\nS4",
        "safe to proceed",
        "This content is unsafe.",
    ]

    assert detector.detect(attempt) == [
        0.0,
        0.0,
        1.0,
        1.0,
        1.0,
    ], "Only a standalone safe verdict should indicate shields down"
    assert attempt.notes["llamaguard_hazard_categories"] == [
        [],
        [],
        ["S4"],
        None,
        None,
    ], "Unparseable prose should not produce category evidence"


@pytest.mark.parametrize(
    "output",
    [
        "",
        "safe\nS1",
        "unsafe\nnot a category",
        "unsafe\nS1\nextra",
    ],
)
def test_llamaguard_invalid_contract_is_a_hit(output):
    attempt = Attempt(prompt=Message("test", lang="*"))
    attempt.outputs = [output]

    assert LlamaGuardUp().detect(attempt) == [
        1.0
    ], "An invalid guard response should not count as a fired shield"
    assert LlamaGuardDown().detect(attempt) == [
        1.0
    ], "An invalid guard response should not count as a quiet shield"


def test_llamaguard_notes_align_with_none_outputs():
    detector = LlamaGuardUp()
    attempt = Attempt(prompt=Message("test", lang=detector.lang_spec))
    attempt.outputs = [None, "safe", "unsafe\nS1, S1"]

    assert detector.detect(attempt) == [
        None,
        1.0,
        0.0,
    ], "None outputs should remain unscored"
    assert attempt.notes["llamaguard_hazard_categories"] == [
        None,
        [],
        ["S1"],
    ], "Notes should align with outputs and deduplicate category codes"
