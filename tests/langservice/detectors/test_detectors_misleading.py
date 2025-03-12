# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import pathlib
import os

from garak import _config
from garak.attempt import Attempt
from garak.detectors.misleading import MustContradictNLI
from garak.detectors.base import HFDetector


@pytest.fixture
def hf_detector():
    local_config_path = str(
        pathlib.Path(__file__).parents[1] / "test_config" / "translation.yaml"
    )
    if os.path.exists(local_config_path) is False:
        pytest.skip("Local config file does not exist, skipping test.")
    _config.load_config(run_config_filename=local_config_path)
    HFDetector.detector_model_path = (
        "garak-llm/roberta-large-snli_mnli_fever_anli_R1_R2_R3-nli"
    )
    HFDetector.detector_target_class = "label"
    HFDetector.tokenizer_kwargs = {"truncation": True, "max_length": 256}
    detector = HFDetector(_config)
    return detector


@pytest.fixture
def must_contradict_NLI_detector():
    local_config_path = str(
        pathlib.Path(__file__).parents[1] / "test_config" / "translation.yaml"
    )
    if os.path.exists(local_config_path) is False:
        pytest.skip("Local config file does not exist, skipping test.")
    _config.load_config(run_config_filename=local_config_path)
    detector = MustContradictNLI(_config)
    return detector


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_must_contradict_NLI_detection(must_contradict_NLI_detector):
    attempt = Attempt(
        prompt="これはテストプロンプトです",
        notes={"pre_translation_prompt": "This is a test prompt."},
        bcp47="ja",
    )
    attempt.outputs = ["こんにちは world", "陰府 の 端 に は 陰府 の 穴 が あ る."]
    attempt.reverse_translator_outputs = (
        must_contradict_NLI_detector.reverse_translator.translate_prompts(
            attempt.all_outputs
        )
    )

    results = must_contradict_NLI_detector.detect(attempt)
    assert results[0] < 0.1, "Detection results do not match expected values"
    assert results[1] < 0.5, "Detection results do not match expected values"


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_hf_detector_detection(hf_detector):
    # Create a sample Attempt with Japanese text
    attempt = Attempt(
        prompt="2人の女性が持ち帰り用の荷物を持ちながら抱き合っている", bcp47="ja"
    )
    attempt.outputs = ["男たちがデリカテッセンの外で喧嘩している"]
    attempt.reverse_translator_outputs = (
        hf_detector.reverse_translator.translate_prompts(attempt.all_outputs)
    )

    # Run the detection
    results = hf_detector.detect(attempt)
    # Verify the results
    assert isinstance(results, list), "Detect method should return a list"
    for result in results:
        assert isinstance(result, float), "Each result should be a float"
        assert 0.0 <= result <= 1.0, "Each result should be between 0.0 and 1.0"
