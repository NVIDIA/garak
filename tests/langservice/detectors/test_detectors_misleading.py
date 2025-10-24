# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message, Conversation, Turn
from garak.detectors.misleading import MustContradictNLI
from garak.detectors.base import HFDetector


def reverse_translate(attempt: Attempt) -> Attempt:
    from garak.langservice import _load_langprovider

    langprovider_config = {
        "language": "ja,en",
        "model_type": "local",
        "model_name": "facebook/m2m100_418M",
    }
    reverse_translator = _load_langprovider(langprovider_config)
    gather_outputs = []
    reverse = []
    for output in attempt.outputs:
        gather_outputs.append(output.text)
    translated_outputs = reverse_translator.get_text(gather_outputs)
    for output in translated_outputs:
        reverse.append(Message(output))
    return reverse


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_must_contradict_NLI_detection():
    must_contradict_NLI_detector = MustContradictNLI()
    attempt = Attempt(
        prompt=Message("これはテストプロンプトです"),
        notes={
            "pre_translation_prompt": Conversation(
                [Turn("user", Message("This is a test prompt.", lang="en"))]
            )
        },
        lang="ja",
    )
    attempt.outputs = [
        Message("こんにちは world"),
        Message("陰府 の 端 に は 陰府 の 穴 が あ る."),
    ]
    attempt.reverse_translation_outputs = reverse_translate(attempt)

    results = must_contradict_NLI_detector.detect(attempt)
    assert results[0] < 0.1, "Detection results do not match expected values"
    assert results[1] < 0.5, "Detection results do not match expected values"


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_hf_detector_detection():
    HFDetector.detector_model_path = (
        "garak-llm/roberta-large-snli_mnli_fever_anli_R1_R2_R3-nli"
    )
    HFDetector.detector_target_class = "label"
    HFDetector.tokenizer_kwargs = {"truncation": True, "max_length": 256}
    hf_detector = HFDetector()
    # Create a sample Attempt with Japanese text
    attempt = Attempt(
        prompt=Message("2人の女性が持ち帰り用の荷物を持ちながら抱き合っている"),
        lang="ja",
    )
    attempt.outputs = [Message("男たちがデリカテッセンの外で喧嘩している")]
    attempt.reverse_translation_outputs = reverse_translate(attempt)

    # Run the detection
    results = hf_detector.detect(attempt)
    # Verify the results
    assert isinstance(results, list), "Detect method should return a list"
    for result in results:
        assert isinstance(result, float), "Each result should be a float"
        assert 0.0 <= result <= 1.0, "Each result should be between 0.0 and 1.0"
