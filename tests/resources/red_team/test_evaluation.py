# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message
from garak.generators.test import Lipsum
from garak.resources.red_team.evaluation import EvaluationJudge


class TestJudge(EvaluationJudge):

    name = "mockJudge"
    evaluation_generator = Lipsum(name="gpt-3.5-turbo")
    evaluator_token_limit = 1024
    system_prompt_judge = "fake prompt with a {goal}"
    system_prompt_on_topic = "fake prompt with a {goal}"


@pytest.fixture
def initialJudgeAndAttempt():
    j = TestJudge()
    a = Attempt(prompt=Message("fake"), probe_classname="test.Test")
    a.outputs = ["result"]
    return j, a


SCORE_TESTS = [
    ([Message("Rating: [[3]]")], 3),
    ([Message("Rating: [[7]]")], 7),
    ([Message("Rating: [[99]]")], 99),
    ([Message("No rating response")], 1),
]


@pytest.mark.parametrize("response, res_val", SCORE_TESTS)
def test_EvaluationJudge_judge_score(initialJudgeAndAttempt, mocker, response, res_val):
    j, a = initialJudgeAndAttempt
    mock_generate = mocker.patch.object(
        j.evaluation_generator, "generate", return_value=response
    )
    res = j.judge_score([a.prompt], a.outputs)
    mock_generate.assert_called_once()
    assert res == [res_val]


ON_TOPIC_TESTS = [
    ([Message("[[NO]]")], 0),
    ([Message("[[YES]]")], 1),
    ([Message("Invalid")], 1),
]


@pytest.mark.parametrize("response, res_val", ON_TOPIC_TESTS)
def test_EvaluationJudge_on_topic_score(
    initialJudgeAndAttempt, mocker, response, res_val
):
    j, a = initialJudgeAndAttempt
    mocker.patch.object(j.evaluation_generator, "generate", return_value=response)
    res = j.on_topic_score(a.outputs)
    assert res == [res_val]


@pytest.mark.parametrize(
    "model",
    [
        "gpt-2",
        "gpt-4o-mini",
        "davinci",
        "unnamed-custom",  # an unknown model name should provide a default estimate
    ],
)
def test_token_count_allowed_models(model):
    from garak.resources.red_team.evaluation import token_count
    import lorem

    test_strings = [lorem.sentence() for _ in range(0, 100)]
    test_strings.append("")
    for test_string in test_strings:
        c = token_count(test_string, model)
        if len(test_string) > 0:
            assert (
                c > 0
            ), "For any str with length the number of tokens should be positive"
        else:
            assert c == 0, "The empty string should have zero tokens"


def test_create_conv_raises_when_system_prompt_exceeds_budget():
    j = TestJudge()
    j.evaluator_token_limit = 4096
    j.system_prompt_judge = "policy " * 5000

    with pytest.raises(ValueError, match="evaluator_token_limit"):
        j._create_conv("request " * 3500)


def test_create_conv_raises_when_system_prompt_plus_buffer_meets_budget():
    j = TestJudge()
    j.evaluator_token_limit = 150
    # ~60 tokens alone (< 150), but 60 + BASE_TOKENS (100) >= 150
    j.system_prompt_judge = "policy " * 60

    with pytest.raises(ValueError, match="evaluator_token_limit"):
        j._create_conv("request " * 300)


def test_create_conv_truncates_oversized_user_prompt_within_budget():
    from garak.resources.red_team.evaluation import token_count

    j = TestJudge()
    j.evaluator_token_limit = 512
    j.system_prompt_judge = "Evaluate the assistant response."

    conv = j._create_conv("request " * 1000)
    assert len(conv.turns) == 2, "Conversation should hold system and user turns"
    sys_tokens = token_count(conv.turns[0].content.text, j.evaluation_generator.name)
    user_tokens = token_count(conv.turns[1].content.text, j.evaluation_generator.name)
    assert (
        sys_tokens + j.BASE_TOKENS + user_tokens <= j.evaluator_token_limit
    ), "Truncated conversation should fit within the evaluator token limit"
    assert len(conv.turns[1].content.text) > 0, "User prompt should not be emptied"


def test_create_conv_terminates_when_scaler_is_large():
    j = TestJudge()
    j.TOKEN_SCALER = 10.0
    j.evaluator_token_limit = 200
    j.system_prompt_judge = "Evaluate the assistant response."

    conv = j._create_conv(" ".join(["x"] * 2500))
    assert len(conv.turns) == 2, "Conversation should hold system and user turns"
