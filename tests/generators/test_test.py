# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import random

import garak._plugins
from garak.attempt import Message, Turn, Conversation
import garak.generators.base
from garak.generators.test import Blank, Repeat, Single, Lipsum, ReasoningLipsum

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
        conv = Conversation([Turn("user", Message(""))])
        out = g.generate(conv, generations_this_call=generations)
        assert isinstance(out, list), ".generate() must return a list"
        assert (
            len(out) == generations
        ), ".generate() must respect generations_per_call param"
        for s in out:
            assert (
                isinstance(s, Message) or s is None
            ), "generate()'s returned list's items must be Turn or None"


def test_generators_test_blank():
    g = Blank(DEFAULT_GENERATOR_NAME)
    conv = Conversation([Turn("user", Message("test"))])
    output = g.generate(conv, generations_this_call=5)
    assert output == [
        Message(""),
        Message(""),
        Message(""),
        Message(""),
        Message(""),
    ], "generators.test.Blank with generations_this_call=5 should return five empty Turns"


def test_generators_test_repeat():
    g = Repeat(DEFAULT_GENERATOR_NAME)
    conv = Conversation([Turn("user", Message(DEFAULT_PROMPT_TEXT))])
    output = g.generate(conv)
    assert output == [
        Message(DEFAULT_PROMPT_TEXT)
    ], "generators.test.Repeat should send back a list of the posed prompt string"


def test_generators_test_single_one():
    g = Single(DEFAULT_GENERATOR_NAME)
    conv = Conversation([Turn("user", Message("test"))])
    output = g.generate(conv)
    assert isinstance(
        output, list
    ), "Single generator .generate() should send back a list"
    assert (
        len(output) == 1
    ), "Single.generate() without generations_this_call should send a list of one Turn"
    assert isinstance(
        output[0], Message
    ), "Single generator output list should contain strings"

    output = g._call_model(conv)
    assert isinstance(output, list), "Single generator _call_model should return a list"
    assert (
        len(output) == 1
    ), "_call_model w/ generations_this_call 1 should return a list of length 1"
    assert isinstance(
        output[0], Message
    ), "Single generator output list should contain Turns"


def test_generators_test_single_many():
    random_generations = random.randint(2, 12)
    g = Single(DEFAULT_GENERATOR_NAME)
    conv = Conversation([Turn("user", Message("test"))])
    output = g.generate(prompt=conv, generations_this_call=random_generations)
    assert isinstance(
        output, list
    ), "Single generator .generate() should send back a list"
    assert (
        len(output) == random_generations
    ), "Single.generate() with generations_this_call should return equal generations"
    for i in range(0, random_generations):
        assert isinstance(
            output[i], Message
        ), "Single generator output list should contain Turns"


def test_generators_test_single_too_many():
    g = Single(DEFAULT_GENERATOR_NAME)
    with pytest.raises(ValueError):
        conv = Conversation([Turn("user", Message("test"))])
        g._call_model(conv, generations_this_call=2)
    assert "Single._call_model should refuse to process generations_this_call > 1"


def test_generators_test_blank_one():
    g = Blank(DEFAULT_GENERATOR_NAME)
    conv = Conversation([Turn("user", Message("test"))])
    output = g.generate(conv)
    assert isinstance(
        output, list
    ), "Blank generator .generate() should send back a list"
    assert (
        len(output) == 1
    ), "Blank generator .generate() without generations_this_call should return a list of length 1"
    assert isinstance(
        output[0], Message
    ), "Blank generator output list should contain Turns"
    assert output[0] == Message(
        ""
    ), "Blank generator .generate() output list should contain Turns"


def test_generators_test_blank_many():
    g = Blank(DEFAULT_GENERATOR_NAME)
    conv = Conversation([Turn("user", Message("test"))])
    output = g.generate(conv, generations_this_call=2)
    assert isinstance(
        output, list
    ), "Blank generator .generate() should send back a list"
    assert (
        len(output) == 2
    ), "Blank generator .generate() w/ generations_this_call=2 should return a list of length 2"
    assert isinstance(
        output[0], Message
    ), "Blank generator output list should contain Turns (first position)"
    assert isinstance(
        output[1], Message
    ), "Blank generator output list should contain Turns (second position)"
    assert output[0] == Message(
        ""
    ), "Blank generator .generate() output list should contain Turns (first position) w empty prompt"
    assert output[1] == Message(
        ""
    ), "Blank generator .generate() output list should contain Turns (second position) w empty prompt"


def _make_conv():
    return Conversation([Turn("user", Message("test"))])


LIPSUM_GENERATIONS = 200


def test_lipsum_default_returns_message():
    g = Lipsum()
    output = g.generate(_make_conv())
    assert len(output) == 1
    assert isinstance(output[0], Message)
    assert len(str(output[0])) > 0, "Lipsum should produce non-empty output"


def test_lipsum_unit_sentence():
    g = Lipsum()
    g.unit = "sentence"
    g.count = 1
    output = g._call_model(_make_conv())
    text = output[0].text
    assert text.endswith("."), "A single lorem sentence should end with a period"
    assert "\n" not in text, "A single sentence should not contain newlines"


def test_lipsum_unit_paragraph():
    g = Lipsum()
    g.unit = "paragraph"
    g.count = 1
    output = g._call_model(_make_conv())
    text = output[0].text
    assert len(text) > 0
    assert text.count(".") > 1, "A paragraph should contain multiple sentences"


def test_lipsum_unit_text():
    g = Lipsum()
    g.unit = "text"
    g.count = 1
    output = g._call_model(_make_conv())
    text = output[0].text
    assert len(text) > 0
    assert "\n" in text, "A text block should contain newlines between paragraphs"


def test_lipsum_count_joins_multiple_units():
    count = 5
    g = Lipsum()
    g.unit = "sentence"
    g.count = count
    output = g._call_model(_make_conv())
    text = output[0].text
    assert (
        text.count(".") >= count
    ), f"count={count} sentences should yield at least {count} stops"


def test_lipsum_invalid_unit_raises():
    g = Lipsum()
    g.unit = "chapter"
    with pytest.raises(ValueError, match="Invalid unit"):
        g._call_model(_make_conv())


def test_lipsum_outputs_vary():
    g = Lipsum()
    results = {g._call_model(_make_conv())[0].text for _ in range(LIPSUM_GENERATIONS)}
    assert len(results) > 1, "Lipsum outputs should vary across calls"


def test_reasoning_lipsum_default_returns_message():
    g = ReasoningLipsum()
    output = g.generate(_make_conv())
    assert len(output) == 1
    assert isinstance(output[0], Message)


def test_reasoning_lipsum_contains_delimiters():
    g = ReasoningLipsum()
    output = g._call_model(_make_conv())
    text = output[0].text
    if g.skip_seq_start:
        assert text.startswith(
            g.skip_seq_start
        ), "Output should begin with skip_seq_start delimiter"
    if g.skip_seq_end:
        assert g.skip_seq_end in text, "Output should contain skip_seq_end delimiter"
        if g.skip_seq_end != g.skip_seq_start:
            assert not text.startswith(
                g.skip_seq_end
            ), "Output should not start with skip_seq_end"
        if g.output_length > 0:
            assert not text.endswith(
                g.skip_seq_end
            ), "Output should end with lipsum, ends with skip_seq_end"


def test_reasoning_lipsum_structure():
    g = ReasoningLipsum()
    output = g._call_model(_make_conv())
    text = output[0].text
    start_idx = text.index(g.skip_seq_start)
    end_idx = text.index(g.skip_seq_end)
    assert start_idx < end_idx, "skip_seq_start must appear before skip_seq_end"
    assert text.startswith(g.skip_seq_start), "Output should start with skip_seq_start"
    after_end = text[end_idx + len(g.skip_seq_end) :]
    assert len(after_end) > 0, "There should be output text after skip_seq_end"


def test_reasoning_lipsum_approximate_total_length():
    g = ReasoningLipsum()
    g.variance = 0.0
    output = g._call_model(_make_conv())
    text = output[0].text
    delimiters_len = len(g.skip_seq_start) + len(g.skip_seq_end)
    expected = g.reasoning_length + g.output_length + delimiters_len
    assert (
        len(text) > expected
    ), f"Default output should be at least {expected} chars, got {len(text)}"
    assert (
        len(text) < 2 * expected
    ), f"Default output should be under 2x {expected} chars, got {len(text)}"


def test_reasoning_lipsum_custom_delimiters():
    g = ReasoningLipsum()
    g.skip_seq_start = "[[REASON]]"
    g.skip_seq_end = "[[/REASON]]"
    output = g._call_model(_make_conv())
    text = output[0].text
    assert text.startswith(g.skip_seq_start)
    assert g.skip_seq_end in text


def test_reasoning_lipsum_custom_lengths():
    g = ReasoningLipsum()
    g.reasoning_length = 5000
    g.output_length = 2000
    g.variance = 0.0
    output = g._call_model(_make_conv())
    text = output[0].text
    end_idx = text.index(g.skip_seq_end)
    reasoning_section = text[len(g.skip_seq_start) : end_idx]
    output_section = text[end_idx + len(g.skip_seq_end) :]
    assert (
        len(reasoning_section) >= g.reasoning_length
    ), f"Reasoning section should be >= {g.reasoning_length} chars, got {len(reasoning_section)}"
    assert (
        len(output_section) >= g.output_length
    ), f"Output section should be >= {g.output_length} chars, got {len(output_section)}"


@pytest.mark.parametrize(
    "unit",
    [
        "sentence",
        "paragraph",
        "text",
    ],
)
def test_reasoning_lipsum_variance_zero_consistent(unit):
    g = ReasoningLipsum()
    g.variance = 0.0
    g.unit = unit
    resp_length = random.randint(10, 300)
    lengths = [
        len(g._generate_lorem(resp_length, 0.0)) for _ in range(LIPSUM_GENERATIONS)
    ]
    assert (
        min(lengths) >= resp_length
    ), f"With variance={g.variance}, total length always be greater than or equal the minimum passed, got {min(lengths)}"


@pytest.mark.parametrize(
    "unit",
    [
        "sentence",
        "paragraph",
        "text",
    ],
)
def test_reasoning_lipsum_variance_produces_variation(unit):
    g = ReasoningLipsum()
    g.variance = random.random()
    g.unit = unit
    resp_length = random.randint(10, 300)
    lengths = [
        len(g._generate_lorem(resp_length, g.variance))
        for _ in range(LIPSUM_GENERATIONS)
    ]
    assert (
        min(lengths) > 0
    ), f"With high variance={g.variance}, output lengths should vary yet not be empty"


def test_reasoning_lipsum_multiple_generations():
    g = ReasoningLipsum()
    output = g._call_model(_make_conv(), generations_this_call=LIPSUM_GENERATIONS)
    assert (
        len(output) == LIPSUM_GENERATIONS
    ), "Should return requested number of generations"
    for msg in output:
        assert isinstance(msg, Message)
        text = msg.text
        assert g.skip_seq_start in text
        assert g.skip_seq_end in text
