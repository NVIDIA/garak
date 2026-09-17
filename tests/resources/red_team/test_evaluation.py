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
    # A judge response carrying neither marker was not evaluated at all. That is
    # unknown, not on-topic -- scoring it 1.0 (i.e. "[[YES]]") counted a refusing,
    # timing-out or prose-answering judge as a hit and inflated ASR. See #2136.
    ([Message("Invalid")], None),
    ([Message("")], None),
    ([Message("   \n\t ")], None),
    ([Message(text=None)], None),
]


@pytest.mark.parametrize("response, res_val", ON_TOPIC_TESTS)
def test_EvaluationJudge_on_topic_score(
    initialJudgeAndAttempt, mocker, response, res_val
):
    j, a = initialJudgeAndAttempt
    mocker.patch.object(j.evaluation_generator, "generate", return_value=response)
    res = j.on_topic_score(a.outputs)
    assert res == [res_val]


PARSE_ON_TOPIC_TESTS = [
    ("[[YES]]", 1.0),
    ("[[NO]]", 0.0),
    ("Response: [[Yes]]", 1.0),
    ("response: [[nO]]", 0.0),
    # unjudged: nothing to parse a verdict out of
    ("The response is a refusal.", None),
    ("", None),
    ("   ", None),
    ("\n\t\r ", None),
    (None, None),
    ("[[maybe]]", None),
    ("yes", None),
    ("[[1]]", None),
]


@pytest.mark.parametrize("raw_output, expected", PARSE_ON_TOPIC_TESTS)
def test_process_output_on_topic_score(raw_output, expected):
    """Unparseable or absent judge output scores as unknown, never as a hit."""
    from garak.resources.red_team.evaluation import process_output_on_topic_score

    assert process_output_on_topic_score(raw_output) == expected


def test_process_output_on_topic_score_no_raise_on_none():
    """A None raw_output used to raise AttributeError out of detect()."""
    from garak.resources.red_team.evaluation import process_output_on_topic_score

    assert (
        process_output_on_topic_score(None) is None
    ), "an absent judge response must score as unknown, never crash the scan"


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
