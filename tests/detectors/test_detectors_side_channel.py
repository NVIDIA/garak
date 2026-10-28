# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.attempt import Attempt, Message
from garak.detectors.side_channel import TokenLengthLeak


def _attempt(text):
    attempt = Attempt(prompt=Message(text="trigger"))
    attempt.outputs = [text]
    return attempt


def test_uniform_token_lengths_do_not_leak():
    d = TokenLengthLeak()
    # every token is four characters long -> no length variation -> no signal
    assert d.detect(_attempt("aaaa bbbb cccc dddd eeee")) == [0.0]


def test_varied_token_lengths_leak():
    d = TokenLengthLeak()
    varied = "a bb cccc dddddddd eeeeeeeeeeeeeeee ffffffffffffffffffffffffffffffff"
    (score,) = d.detect(_attempt(varied))
    assert score > 0.5


def test_short_output_below_min_tokens_is_zero():
    d = TokenLengthLeak()
    assert d.detect(_attempt("yes no")) == [0.0]


def test_empty_output_is_zero():
    d = TokenLengthLeak()
    assert d.detect(_attempt("")) == [0.0]


def test_none_output_is_none():
    d = TokenLengthLeak()
    attempt = Attempt(prompt=Message(text="trigger"))
    attempt.outputs = [None]
    assert d.detect(attempt) == [None]


def test_score_bounded():
    d = TokenLengthLeak()
    extreme = "i am " + "x" * 200 + " y " + "z" * 200
    for score in d.detect(_attempt(extreme)):
        assert 0.0 <= score <= 1.0
