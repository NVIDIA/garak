# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt
from garak.detectors.shields import Up, Down

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
        "fail this request"
    ]
    
    for response in default_responses:
        attempt = Attempt(prompt="test")
        attempt.outputs = [response]
        results = up_detector.detect(attempt)
        assert results == [0.0], f"Up detector should trigger (return 0.0) for '{response}'"

def test_up_detector_non_matching(up_detector):
    """Test that Up detector correctly handles non-matching content"""
    safe_responses = [
        "This is a normal response",
        "Everything looks good",
        "Let me help you with that",
    ]
    
    for response in safe_responses:
        attempt = Attempt(prompt="test")
        attempt.outputs = [response]
        results = up_detector.detect(attempt)
        assert results == [1.0], f"Up detector should not trigger (return 1.0) for '{response}'"

def test_up_detector_custom_strings():
    """Test that Up detector respects custom upstrings configuration"""
    custom_strings = ["forbidden", "restricted"]
    detector = Up()
    detector.substrings = custom_strings
    
    attempt = Attempt(prompt="test")
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
        "clear for processing"
    ]
    
    for response in default_responses:
        attempt = Attempt(prompt="test")
        attempt.outputs = [response]
        results = down_detector.detect(attempt)
        assert results == [0.0], f"Down detector should trigger (return 0.0) for '{response}'"

def test_down_detector_non_matching(down_detector):
    """Test that Down detector correctly handles non-matching content"""
    unsafe_responses = [
        "This content is blocked",
        "Request denied",
        "Content flagged",
    ]
    
    for response in unsafe_responses:
        attempt = Attempt(prompt="test")
        attempt.outputs = [response]
        results = down_detector.detect(attempt)
        assert results == [1.0], f"Down detector should not trigger (return 1.0) for '{response}'"

def test_down_detector_custom_strings():
    """Test that Down detector respects custom downstrings configuration"""
    custom_strings = ["approved", "permitted"]
    detector = Down()
    detector.substrings = custom_strings
    
    attempt = Attempt(prompt="test")
    attempt.outputs = ["approved for use"]
    results = detector.detect(attempt)
    assert results == [0.0], "Down detector should trigger for custom string"

def test_multiple_outputs():
    """Test both detectors with multiple outputs"""
    up_detector = Up()
    down_detector = Down()
    
    attempt = Attempt(prompt="test")
    attempt.outputs = ["unsafe content", "normal response", "block this"]
    
    up_results = up_detector.detect(attempt)
    assert up_results == [0.0, 1.0, 0.0], "Up detector failed on multiple outputs"
    
    attemptd = Attempt(prompt="test")
    attemptd.outputs = ["safe content", "blocked response", "allow this"]
    down_results = down_detector.detect(attemptd)
    assert down_results == [0.0, 1.0, 0.0], "Down detector failed on multiple outputs"

def test_case_sensitivity():
    """Test case sensitivity behavior for both detectors"""
    up_detector = Up()
    down_detector = Down()
    
    # Test Up detector
    attempt = Attempt(prompt="test")
    attempt.outputs = ["UNSAFE content", "Block THIS", "unsafe"]
    
    # Case sensitive
    results = up_detector.detect(attempt, case_sensitive=True)
    assert results == [1.0, 1.0, 0.0], "Up detector case sensitive check failed"
    
    # Case insensitive
    results = up_detector.detect(attempt, case_sensitive=False)
    assert results == [0.0, 0.0, 0.0], "Up detector case insensitive check failed"
    
    # Test Down detector
    attemptd = Attempt(prompt="test")
    attemptd.outputs = ["SAFE content", "Allow THIS", "safe"]
    
    # Case sensitive
    results = down_detector.detect(attemptd, case_sensitive=True)
    assert results == [1.0, 1.0, 0.0], "Down detector case sensitive check failed"
    
    # Case insensitive
    results = down_detector.detect(attemptd, case_sensitive=False)
    assert results == [0.0, 0.0, 0.0], "Down detector case insensitive check failed"
