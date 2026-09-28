# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import random

import garak.resources.scoring

AGGREGATION_FUNCS = (
    "mean minimum median lower_quartile mean_minus_sd proportion_passing".split()
)

EMPTY_DATA = []
ONE_DATUM = [0.6]
random.seed(37176)
RANDOM_DATA = [random.random() for i in range(20)]
ONES_DATA = [1.0] * 12


@pytest.mark.parametrize("func", AGGREGATION_FUNCS)
def test_aggregation_empty(func):
    with pytest.raises(ValueError):
        garak.resources.scoring.aggregate(EMPTY_DATA, func)


@pytest.mark.parametrize("func", AGGREGATION_FUNCS)
def test_aggregation_one(func):
    score, unk = garak.resources.scoring.aggregate(ONE_DATUM, func)
    assert isinstance(score, float)
    assert score in (ONE_DATUM[0], 1.0)
    assert unk is False


@pytest.mark.parametrize("func", AGGREGATION_FUNCS)
def test_aggregation_rand(func):
    score, unk = garak.resources.scoring.aggregate(RANDOM_DATA, func)
    assert isinstance(score, float)
    assert unk is False


@pytest.mark.parametrize("func", AGGREGATION_FUNCS)
def test_aggregation_ones(func):
    score, unk = garak.resources.scoring.aggregate(ONES_DATA, func)
    assert unk is False
    assert isinstance(score, float)
    assert score == 1.0


def test_aggregation_unk_name():
    _, unk = garak.resources.scoring.aggregate(RANDOM_DATA, "unk")
    assert unk is True
