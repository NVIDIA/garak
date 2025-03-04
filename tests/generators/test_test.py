# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import random

import garak._plugins
from garak.attempt import Turn
import garak.generators.base
from garak.generators.test import Blank, Repeat, Single

TEST_GENERATORS = [
    a
    for a, b in garak._plugins.enumerate_plugins("generators")
    if b is True and a.startswith("generators.test")
]

DEFAULT_GENERATOR_NAME = "garak test"
DEFAULT_PROMPT_TEXT = "especially the lies"


@pytest.mark.parametrize("klassname", TEST_GENERATORS)
def test_test_instantiate(klassname):
    g = garak._plugins.load_plugin(klassname)
    assert isinstance(g, garak.generators.base.Generator)


@pytest.mark.parametrize("klassname", TEST_GENERATORS)
def test_test_gen(klassname):
    g = garak._plugins.load_plugin(klassname)
    for generations in (1, 50):
        out = g.generate(Turn(""), generations_this_call=generations)
        assert isinstance(out, list), ".generate() must return a list"
        assert (
            len(out) == generations
        ), ".generate() must respect generations_per_call param"
        for s in out:
            assert (
                isinstance(s, Turn) or s is None
            ), "generate()'s returned list's items must be Turn or None"


def test_generators_test_blank():
    g = Blank(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"), generations_this_call=5)
    assert output == [
        Turn(""),
        Turn(""),
        Turn(""),
        Turn(""),
        Turn(""),
    ], "generators.test.Blank with generations_this_call=5 should return five empty Turns"


def test_generators_test_repeat():
    g = Repeat(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn(DEFAULT_PROMPT_TEXT))
    assert output == [
        Turn(DEFAULT_PROMPT_TEXT)
    ], "generators.test.Repeat should send back a list of the posed prompt string"


def test_generators_test_single_one():
    g = Single(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"))
    assert isinstance(
        output, list
    ), "Single generator .generate() should send back a list"
    assert (
        len(output) == 1
    ), "Single.generate() without generations_this_call should send a list of one Turn"
    assert isinstance(
        output[0], Turn
    ), "Single generator output list should contain strings"

    output = g._call_model(prompt=Turn("test"))
    assert isinstance(output, list), "Single generator _call_model should return a list"
    assert (
        len(output) == 1
    ), "_call_model w/ generations_this_call 1 should return a list of length 1"
    assert isinstance(
        output[0], Turn
    ), "Single generator output list should contain Turns"


def test_generators_test_single_many():
    random_generations = random.randint(2, 12)
    g = Single(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"), generations_this_call=random_generations)
    assert isinstance(
        output, list
    ), "Single generator .generate() should send back a list"
    assert (
        len(output) == random_generations
    ), "Single.generate() with generations_this_call should return equal generations"
    for i in range(0, random_generations):
        assert isinstance(
            output[i], Turn
        ), "Single generator output list should contain Turns"


def test_generators_test_single_too_many():
    g = Single(DEFAULT_GENERATOR_NAME)
    with pytest.raises(ValueError):
        output = g._call_model(prompt=Turn("test"), generations_this_call=2)
    assert "Single._call_model should refuse to process generations_this_call > 1"


def test_generators_test_blank_one():
    g = Blank(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"))
    assert isinstance(
        output, list
    ), "Blank generator .generate() should send back a list"
    assert (
        len(output) == 1
    ), "Blank generator .generate() without generations_this_call should return a list of length 1"
    assert isinstance(
        output[0], Turn
    ), "Blank generator output list should contain Turns"
    assert output[0] == Turn(
        ""
    ), "Blank generator .generate() output list should contain Turns"


def test_generators_test_blank_many():
    g = Blank(DEFAULT_GENERATOR_NAME)
    output = g.generate(prompt=Turn("test"), generations_this_call=2)
    assert isinstance(
        output, list
    ), "Blank generator .generate() should send back a list"
    assert (
        len(output) == 2
    ), "Blank generator .generate() w/ generations_this_call=2 should return a list of length 2"
    assert isinstance(
        output[0], Turn
    ), "Blank generator output list should contain Turns (first position)"
    assert isinstance(
        output[1], Turn
    ), "Blank generator output list should contain Turns (second position)"
    assert output[0] == Turn(
        ""
    ), "Blank generator .generate() output list should contain Turns (first position) w empty prompt"
    assert output[1] == Turn(
        ""
    ), "Blank generator .generate() output list should contain Turns (second position) w empty prompt"
