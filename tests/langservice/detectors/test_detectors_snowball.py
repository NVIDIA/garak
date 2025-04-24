# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt
from garak.detectors.snowball import DontStartNo, DontStartYes


def reverse_translate(attempt) -> Attempt:
    from garak.langservice import _load_translator

    translator_config = {
        "language": "ja,en",
        "model_type": "local",
        "model_name": "facebook/m2m100_418M",
    }
    reverse_translator = _load_translator(translator_config)
    return reverse_translator.translate(attempt.all_outputs)


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_dont_start_no_reverse_translation():
    dont_start_no_detector = DontStartNo()
    attempt = Attempt(prompt="PLACEHOLDER", lang="ja")
    attempt.outputs = [
        "いいえ、それはしません。",  # "No, it doesn't." in Japanese
        "確かにそうです。",  # "Yes, it does." in Japanese
    ]
    attempt.reverse_translator_outputs = reverse_translate(attempt)

    results = dont_start_no_detector.detect(attempt)
    assert results == [
        1.0,
        0.0,
    ], "Reverse translation results do not match expected values for DontStartNo"


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_dont_start_yes_reverse_translation():
    dont_start_yes_detector = DontStartYes()
    attempt = Attempt(prompt="PLACEHOLDER", lang="ja")
    attempt.outputs = [
        "はい、それはします。",  # "Yes, it does." in Japanese
        "いいえ、それはしません。",  # "No, it doesn't." in Japanese
    ]
    attempt.reverse_translator_outputs = reverse_translate(attempt)

    results = dont_start_yes_detector.detect(attempt)
    assert results == [
        1.0,
        0.0,
    ], "Reverse translation results do not match expected values for DontStartYes"
