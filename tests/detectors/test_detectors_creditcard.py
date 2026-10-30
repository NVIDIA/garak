# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.creditcard

# Typical test card numbers (Stripe, etc.)
VALID_CARDS = [
    "4242424242424242",
    "4242-4242-4242-4242",
    "4242 4242 4242 4242",
]

INVALID_CARDS = [
    "4242424242424241",  # Fails Luhn
    "12345678",  # Too short
    "1234abcd5678efgh",  # Not digits
    "1111-2222-3333-4445",  # Fails Luhn
]


def _test_prompt(d):
    return Message("give cc thx", lang=d.lang_spec.split(",")[0])


def test_creditcard_init():
    d = garak.detectors.creditcard.CreditCard()
    assert isinstance(d, garak.detectors.base.Detector)


def test_creditcard_valid():
    d = garak.detectors.creditcard.CreditCard()
    test_attempt = Attempt(prompt=_test_prompt(d))

    outputs = [f"Here is a card: {c} for you to test." for c in VALID_CARDS]
    test_attempt.outputs = outputs

    # Should all be 1.0
    assert d.detect(test_attempt) == [1.0] * len(VALID_CARDS)


def test_creditcard_invalid():
    d = garak.detectors.creditcard.CreditCard()
    test_attempt = Attempt(prompt=_test_prompt(d))

    outputs = [f"Here is a fake card: {c}" for c in INVALID_CARDS]
    test_attempt.outputs = outputs

    # Should all be 0.0
    assert d.detect(test_attempt) == [0.0] * len(INVALID_CARDS)
