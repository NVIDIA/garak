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
    (
        garak.detectors.judge.Jailbreak,
        [Message("Invalid")],
        1,
    ),  # Default to jailbreak if unclear
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


def _build_override_config(klass_name: str, **klass_overrides):
    """Helper: build a config_root dict with class-specific overrides for a judge detector."""
    return {
        "detectors": {
            "judge": {
                "detector_model_config": {"api_key": "fake"},
                klass_name: klass_overrides,
            },
        }
    }


def _run_detect_and_get_system_prompt(d, mocker, judge_response):
    """Helper: mock evaluation_generator, run detect on a one-output attempt, return system message text."""
    mock_generate = mocker.patch.object(
        d.evaluation_generator, "generate", return_value=judge_response
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="prompt"))
    a.outputs = [Message("output")]
    d.detect(a)
    return mock_generate.call_args_list[0].args[0].last_message("system").text


def test_modelasjudge_default_prompt_used(judge_config, mocker):
    """Without override the built-in _goal_system_prompt is sent, with {goal} substituted."""
    d = garak.detectors.judge.ModelAsJudge(config_root=judge_config)
    assert (
        d.system_prompt_judge is None
    ), "DEFAULT_PARAMS exposes the override key as None"
    sys_msg = _run_detect_and_get_system_prompt(d, mocker, [Message("Rating: [[5]]")])
    assert (
        "Rate the response on a scale from 1 to 10" in sys_msg
    ), "built-in goal prompt template must be used when no override is configured"
    assert "{goal}" not in sys_msg, "the {goal} placeholder must be substituted"


def test_refusal_default_prompt_used(judge_config):
    """Without override Refusal sets system_prompt_on_topic to the built-in refusal classifier prompt."""
    d = garak.detectors.judge.Refusal(config_root=judge_config)
    assert (
        d.system_prompt_on_topic == d._refusal_system_prompt
    ), "default Refusal prompt must be the built-in classifier prompt"


def test_jailbreak_default_prompt_used(judge_config):
    """Without override Jailbreak sets system_prompt_on_topic to the built-in JailbreakBench prompt."""
    d = garak.detectors.judge.Jailbreak(config_root=judge_config)
    assert (
        d.system_prompt_on_topic == d._jailbreak_system_prompt
    ), "default Jailbreak prompt must be the built-in JailbreakBench classifier prompt"


OVERRIDE_TESTS = [
    (
        garak.detectors.judge.ModelAsJudge,
        "system_prompt_judge",
        "Custom rating prompt for {goal}. Output [[N]].",
        [Message("Rating: [[5]]")],
    ),
    (
        garak.detectors.judge.Refusal,
        "system_prompt_on_topic",
        "Custom refusal classifier. Output [[YES]] or [[NO]].",
        [Message("[[YES]]")],
    ),
    (
        garak.detectors.judge.Jailbreak,
        "system_prompt_on_topic",
        "Custom jailbreak classifier. Output [[YES]] or [[NO]].",
        [Message("[[YES]]")],
    ),
]


@pytest.mark.parametrize(
    "klass, override_key, override_value, response", OVERRIDE_TESTS
)
def test_override_prompt_via_config(
    klass, override_key, override_value, response, mocker
):
    """User-supplied system prompt via DEFAULT_PARAMS reaches the judge model."""
    overrides = {override_key: override_value}
    if klass is garak.detectors.judge.ModelAsJudge:
        # avoid plugin_info lookup for the {goal} substitution
        overrides["detector_goal"] = "test goal"
    config = _build_override_config(klass.__name__, **overrides)
    d = klass(config_root=config)
    sys_msg = _run_detect_and_get_system_prompt(d, mocker, response)
    if klass is garak.detectors.judge.ModelAsJudge:
        assert (
            sys_msg == "Custom rating prompt for test goal. Output [[N]]."
        ), "custom prompt must reach the judge with {goal} substituted"
    else:
        assert sys_msg == override_value, "custom prompt must reach the judge verbatim"


def test_modelasjudge_no_goal_placeholder_skips_plugin_info(mocker):
    """When the (user or default) prompt has no {goal}, _plugins.plugin_info must not be invoked."""
    config = _build_override_config(
        "ModelAsJudge",
        system_prompt_judge="Rate this on 1-10. Output [[N]].",
    )
    d = garak.detectors.judge.ModelAsJudge(config_root=config)
    plugin_info_mock = mocker.patch("garak._plugins.plugin_info")
    mocker.patch.object(
        d.evaluation_generator, "generate", return_value=[Message("Rating: [[5]]")]
    )
    a = Attempt(probe_classname="test.Test", prompt=Message(text="prompt"))
    a.outputs = [Message("output")]
    d.detect(a)
    plugin_info_mock.assert_not_called()


def test_jailbreak_legacy_custom_system_prompt_is_ignored(mocker):
    """The pre-refactor `custom_system_prompt` key is no longer recognised.

    Documents the breaking change introduced when standardising the override
    key across ModelAsJudge / Refusal / Jailbreak.
    """
    config = _build_override_config(
        "Jailbreak", custom_system_prompt="this string must be ignored"
    )
    d = garak.detectors.judge.Jailbreak(config_root=config)
    assert (
        d.system_prompt_on_topic == d._jailbreak_system_prompt
    ), "legacy custom_system_prompt key must not override the default prompt"


def test_modelasjudge_custom_prompt_with_unrelated_braces(mocker):
    """str.replace must tolerate unrelated brace tokens (which would break .format)."""
    config = _build_override_config(
        "ModelAsJudge",
        system_prompt_judge="Rate {arbitrary_token} for {goal}. Output [[N]].",
        detector_goal="test goal",
    )
    d = garak.detectors.judge.ModelAsJudge(config_root=config)
    sys_msg = _run_detect_and_get_system_prompt(d, mocker, [Message("Rating: [[5]]")])
    assert (
        sys_msg == "Rate {arbitrary_token} for test goal. Output [[N]]."
    ), "only {goal} should be substituted; other curly tokens must survive verbatim"
