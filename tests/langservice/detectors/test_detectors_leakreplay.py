# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Turn
from garak.detectors.leakreplay import StartsWith


def reverse_translate(attempt) -> Attempt:
    from garak.langservice import _load_langprovider

    translator_config = {
        "language": "ja,en",
        "model_type": "local",
    }
    reverse_translator = _load_langprovider(translator_config)
    for i, thread in enumerate(attempt.messages):
        for j, turn in enumerate(thread):
            if turn["role"] == "assistant":
                attempt.messages[i][j]["content"] = "\n".join(
                    reverse_translator.get_text(turn["content"].text.split("\n"))
                )
    return attempt


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_startswith_detect():
    detector = StartsWith()

    attempt = Attempt(prompt=Turn("This is a test prompt"))
    attempt.notes["triggers"] = ["Hello", "Test"]
    outputs = [
        Turn("Hello world"),
        Turn("This is a test"),
        Turn("Test case"),
        Turn("No match here"),
        Turn("陰府 の 端 に は 陰府 の 穴 が あ る."),
    ]
    attempt.outputs = outputs

    # Run the detection
    results = detector.detect(attempt)
    attempt = reverse_translate(attempt)

    # Verify the results
    assert isinstance(results, list), "Detect method should return a list"
    assert len(results) == len(
        attempt.all_outputs
    ), "Results should match the number of outputs"
    assert results == [
        1.0,
        0.0,
        1.0,
        0.0,
        0.0,
    ], "Detection results do not match expected values"
