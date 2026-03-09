# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.judge
from garak.detectors.judge import MulticlassJudge
from garak.exception import BadGeneratorException

VALID_JSON_RESPONSE = json.dumps(
    {
        "complied": {"percentage": 85, "explanation": "The model complied."},
        "rejected": {"percentage": 10, "explanation": "Minor hedging."},
        "alternative": {"percentage": 5, "explanation": "None."},
        "other": {"percentage": 0, "explanation": "N/A."},
    }
)

LOW_SCORE_JSON_RESPONSE = json.dumps(
    {
        "complied": {"percentage": 30, "explanation": "Mostly refused."},
        "rejected": {"percentage": 60, "explanation": "Clear refusal."},
        "alternative": {"percentage": 10, "explanation": "Some redirect."},
        "other": {"percentage": 0, "explanation": "N/A."},
    }
)


@pytest.fixture
def judge_config():
    return {
        "detectors": {
            "judge": {
                "detector_model_config": {
                    "api_key": "fake",
                },
            },
        }
    }


def test_class_init(judge_config):
    d = MulticlassJudge(config_root=judge_config)
    assert isinstance(d, garak.detectors.base.Detector)
    assert isinstance(d, garak.detectors.judge.ModelAsJudge)


def test_model_as_judge_type():
    config = {
        "detectors": {
            "judge": {
                "detector_model_type": "test",
                "detector_model_name": "Test",
            },
        }
    }
    with pytest.raises(BadGeneratorException) as exc_info:
        MulticlassJudge(config_root=config)
    assert "must be compatible with" in str(exc_info.value)


def test_parse_json_response(judge_config):
    d = MulticlassJudge(config_root=judge_config)
    score, parsed = d._parse_response(VALID_JSON_RESPONSE)
    assert score == 85
    assert parsed["complied"]["percentage"] == 85
    assert parsed["rejected"]["percentage"] == 10


def test_parse_json_code_fenced(judge_config):
    d = MulticlassJudge(config_root=judge_config)
    fenced = f"```json\n{VALID_JSON_RESPONSE}\n```"
    score, parsed = d._parse_response(fenced)
    assert score == 85
    assert parsed is not None


def test_parse_json_malformed(judge_config):
    d = MulticlassJudge(config_root=judge_config)
    score, parsed = d._parse_response("this is not json {{{")
    assert score is None
    assert parsed is None


def test_parse_json_missing_keys(judge_config):
    d = MulticlassJudge(config_root=judge_config)
    incomplete = json.dumps({"rejected": {"percentage": 90, "explanation": "Refused."}})
    score, parsed = d._parse_response(incomplete)
    assert score is None
    assert parsed is not None
    assert parsed["rejected"]["percentage"] == 90


def test_parse_rating_fallback(judge_config):
    config = judge_config.copy()
    config["detectors"] = {
        "judge": {
            "MulticlassJudge": {"response_format": "rating"},
            "detector_model_config": {"api_key": "fake"},
        }
    }
    d = MulticlassJudge(config_root=config)
    score, parsed = d._parse_response("Rating: [[8]]")
    assert score == 8.0
    assert parsed is None


def test_strip_code_fences():
    assert MulticlassJudge._strip_code_fences('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert MulticlassJudge._strip_code_fences('```\n{"a": 1}\n```') == '{"a": 1}'
    assert MulticlassJudge._strip_code_fences('{"a": 1}') == '{"a": 1}'


def test_threshold_boundary(judge_config):
    d = MulticlassJudge(config_root=judge_config)
    # Default confidence_cutoff is 70

    # Exactly at cutoff -> 1.0
    at_cutoff = json.dumps(
        {
            "complied": {"percentage": 70, "explanation": "Borderline."},
            "rejected": {"percentage": 30, "explanation": ""},
            "alternative": {"percentage": 0, "explanation": ""},
            "other": {"percentage": 0, "explanation": ""},
        }
    )
    score, _ = d._parse_response(at_cutoff)
    assert score == 70
    assert score >= d.confidence_cutoff  # should map to 1.0

    # Below cutoff -> 0.0
    below = json.dumps(
        {
            "complied": {"percentage": 69, "explanation": "Below threshold."},
            "rejected": {"percentage": 31, "explanation": ""},
            "alternative": {"percentage": 0, "explanation": ""},
            "other": {"percentage": 0, "explanation": ""},
        }
    )
    score, _ = d._parse_response(below)
    assert score == 69
    assert score < d.confidence_cutoff  # should map to 0.0


def test_detect_integration(judge_config, mocker):
    d = MulticlassJudge(config_root=judge_config)
    mock_generate = mocker.patch.object(
        d.evaluation_generator,
        "generate",
        return_value=[Message(VALID_JSON_RESPONSE)],
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="How to do X?"))
    a.outputs = [Message("Sure, here is how...")]
    results = d.detect(a)

    mock_generate.assert_called_once()
    assert len(results) == 1
    assert results[0] == 1.0  # 85 >= 70 cutoff
    assert "multiclass_scores" in a.notes
    assert a.notes["multiclass_scores"][0]["complied"]["percentage"] == 85


def test_detect_low_score(judge_config, mocker):
    d = MulticlassJudge(config_root=judge_config)
    mocker.patch.object(
        d.evaluation_generator,
        "generate",
        return_value=[Message(LOW_SCORE_JSON_RESPONSE)],
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="How to do X?"))
    a.outputs = [Message("I cannot help with that.")]
    results = d.detect(a)

    assert len(results) == 1
    assert results[0] == 0.0  # 30 < 70 cutoff


def test_detect_none_output(judge_config, mocker):
    d = MulticlassJudge(config_root=judge_config)
    mocker.patch.object(
        d.evaluation_generator,
        "generate",
        return_value=[Message(VALID_JSON_RESPONSE)],
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="test"))
    a.outputs = [None, Message("response")]
    results = d.detect(a)

    assert len(results) == 2
    assert results[0] is None
    assert results[1] == 1.0


def test_config_override(judge_config):
    config = {
        "detectors": {
            "judge": {
                "MulticlassJudge": {
                    "score_key": "rejected",
                    "score_field": "confidence",
                    "score_scale": 100,
                    "confidence_cutoff": 50,
                },
                "detector_model_config": {"api_key": "fake"},
            },
        }
    }
    d = MulticlassJudge(config_root=config)
    assert d.score_key == "rejected"
    assert d.score_field == "confidence"
    assert d.confidence_cutoff == 50

    response = json.dumps(
        {
            "rejected": {"confidence": 80, "explanation": "Clear refusal."},
            "complied": {"confidence": 20, "explanation": ""},
        }
    )
    score, parsed = d._parse_response(response)
    assert score == 80
    assert parsed["rejected"]["confidence"] == 80


def test_detect_malformed_json_returns_none(judge_config, mocker):
    d = MulticlassJudge(config_root=judge_config)
    mocker.patch.object(
        d.evaluation_generator,
        "generate",
        return_value=[Message("not valid json at all")],
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="test"))
    a.outputs = [Message("response")]
    results = d.detect(a)

    assert len(results) == 1
    assert results[0] is None
    assert a.notes["multiclass_scores"][0] is None
