# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.judge
from garak.exception import BadGeneratorException

DETECTOR_CLASSES = [
    garak.detectors.judge.ModelAsJudge, 
    garak.detectors.judge.Refusal,
    garak.detectors.judge.Jailbreak,
]


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


@pytest.mark.parametrize("klass", DETECTOR_CLASSES)
def test_class_init(judge_config, klass):
    d = klass(config_root=judge_config)
    assert isinstance(d, garak.detectors.base.Detector)


@pytest.mark.parametrize("klass", DETECTOR_CLASSES)
def test_model_as_judge_type(klass):
    judge_config = {
        "detectors": {
            "judge": {
                "detector_model_type": "test",
                "detector_model_name": "Test",
            },
        }
    }
    with pytest.raises(BadGeneratorException) as exc_info:
        klass(config_root=judge_config)
    assert "must be compatible with" in str(exc_info.value)


DETECT_TESTS = [
    (garak.detectors.judge.ModelAsJudge, [Message("Rating: [[3]]")], 0),
    (garak.detectors.judge.ModelAsJudge, [Message("Rating: [[7]]")], 1),
    (garak.detectors.judge.ModelAsJudge, [Message("Rating: [[11]]")], 1),
    (garak.detectors.judge.ModelAsJudge, [Message("No rating response")], 0),
    (garak.detectors.judge.Refusal, [Message("[[NO]]")], 0),
    (garak.detectors.judge.Refusal, [Message("[[YES]]")], 1),
    (
        garak.detectors.judge.Refusal,
        [Message("Invalid")],
        1,
    ),  # if the judge cannot determine on_topic consider response as refusal
    # Jailbreak detector tests - uses [[YES]]/[[NO]] format
    (garak.detectors.judge.Jailbreak, [Message("[[NO]]")], 0),  # Safe response
    (garak.detectors.judge.Jailbreak, [Message("[[YES]]")], 1),  # Jailbreak detected
    (garak.detectors.judge.Jailbreak, [Message("Invalid")], 1),  # Default to jailbreak if unclear
]


@pytest.mark.parametrize("klass, response, res_val", DETECT_TESTS)
def test_klass_detect(judge_config, mocker, klass, response, res_val):
    d = klass(config_root=judge_config)
    mock_generate = mocker.patch.object(
        d.evaluation_generator, "generate", return_value=response
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="test prompt"))
    a.outputs = [Message("fake")]
    res = d.detect(a)
    mock_generate.assert_called_once()
    assert (
        len(mock_generate.call_args_list[0].args[0].turns) > 1
    ), "the conversation passed to the judge model must have more than one turn, the system prompt and the evaluated value"
    assert isinstance(
        mock_generate.call_args_list[0].args[0].last_message("system"), Message
    ), "a system message must be found in the conversation passed to the judge model"
    assert len(a.outputs) == len(res)
    assert [res_val * len(a.outputs)] == res


class TestJailbreakOnlyAdversarial:
    """Test JailbreakOnlyAdversarial detector that filters by is_adversarial flag"""

    def test_non_adversarial_returns_none(self, judge_config, mocker):
        """Non-adversarial attempts should return None (skipped)"""
        d = garak.detectors.judge.JailbreakOnlyAdversarial(config_root=judge_config)
        # Mock the generator - should NOT be called for non-adversarial
        mock_generate = mocker.patch.object(
            d.evaluation_generator, "generate", return_value=[Message("[[YES]]")]
        )
        
        a = Attempt(probe_classname="test.Test", prompt=Message(text="test prompt"))
        a.outputs = [Message("fake response")]
        a.notes = {"is_adversarial": False}
        
        res = d.detect(a)
        
        # Should return None without calling the judge
        mock_generate.assert_not_called()
        assert res == [None]

    def test_adversarial_evaluates_normally(self, judge_config, mocker):
        """Adversarial attempts should be evaluated by the judge"""
        d = garak.detectors.judge.JailbreakOnlyAdversarial(config_root=judge_config)
        mock_generate = mocker.patch.object(
            d.evaluation_generator, "generate", return_value=[Message("[[YES]]")]
        )
        
        a = Attempt(probe_classname="test.Test", prompt=Message(text="test prompt"))
        a.outputs = [Message("fake response")]
        a.notes = {"is_adversarial": True, "attack_goal": "test goal"}
        
        res = d.detect(a)
        
        # Should call the judge and return the result
        mock_generate.assert_called_once()
        assert res == [1.0]  # [[YES]] means jailbreak detected

    def test_missing_is_adversarial_defaults_to_true(self, judge_config, mocker):
        """Attempts without is_adversarial flag should be evaluated (default True)"""
        d = garak.detectors.judge.JailbreakOnlyAdversarial(config_root=judge_config)
        mock_generate = mocker.patch.object(
            d.evaluation_generator, "generate", return_value=[Message("[[NO]]")]
        )
        
        a = Attempt(probe_classname="test.Test", prompt=Message(text="test prompt"))
        a.outputs = [Message("fake response")]
        a.notes = {}  # No is_adversarial flag
        
        res = d.detect(a)
        
        # Should evaluate since default is True
        mock_generate.assert_called_once()
        assert res == [0.0]  # [[NO]] means safe
