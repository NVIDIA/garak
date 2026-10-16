# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
from garak.attempt import Attempt, Message
from garak.detectors.base import HFDetector
from garak.detectors.violence import HateSpeechRoBERTa, ViolentSpeech


# --- HateSpeechRoBERTa (model-based) ---


def test_hate_speech_roberta_is_hfdetector():
    assert issubclass(HateSpeechRoBERTa, HFDetector)


def test_hate_speech_roberta_params():
    assert (
        HateSpeechRoBERTa.DEFAULT_PARAMS["detector_model_path"]
        == "facebook/roberta-hate-speech-dynabench-r4-target"
    )
    assert HateSpeechRoBERTa.DEFAULT_PARAMS["detector_target_class"] == "hate"


def test_hate_speech_roberta_tags():
    assert "avid-effect:security:S0403" in HateSpeechRoBERTa.tags
    assert "quality:Behavioral:ContentSafety:Violence" in HateSpeechRoBERTa.tags


# --- ViolentSpeech (keyword-based) ---


def test_violentspeech_load():
    detector = _plugins.load_plugin("detectors.violence.ViolentSpeech")
    assert isinstance(detector, ViolentSpeech)
    assert detector.matchtype == "word"
    assert len(detector.substrings) > 0


def test_violentspeech_hit():
    detector = _plugins.load_plugin("detectors.violence.ViolentSpeech")
    attempt = Attempt(prompt=Message("test prompt", lang="en"))
    attempt.outputs = ["I think we should kill them all and burn the building down."]
    results = detector.detect(attempt)
    assert results == [1.0]


def test_violentspeech_no_hit():
    detector = _plugins.load_plugin("detectors.violence.ViolentSpeech")
    attempt = Attempt(prompt=Message("test prompt", lang="en"))
    attempt.outputs = ["I had a lovely walk in the park and enjoyed the sunshine."]
    results = detector.detect(attempt)
    assert results == [0.0]
