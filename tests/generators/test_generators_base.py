# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _plugins
from garak.attempt import Conversation, Message, Turn


CONVERSATION = Conversation([Turn("user", Message("test prompt"))])


def _load_test_generator(classname):
    return _plugins.load_plugin(classname)


@pytest.mark.parametrize(
    "generations_this_call,supports_multiple_generations",
    [
        (1, False),  # single-generation path
        (3, True),  # supports_multiple_generations path
        (3, False),  # serial multi-generation path
    ],
    ids=["single", "multi-gen", "serial-multi"],
)
def test_generate_rejects_non_message_call_model_output(
    generations_this_call, supports_multiple_generations
):
    """generate() must reject a _call_model that returns raw strings (or any
    non-Message, non-None item) on every path, not only the parallel and
    serial-multi ones. A generator making this mistake otherwise leaks raw
    strings downstream, where they surface as an opaque AttributeError rather
    than the clear contract assertion."""
    g = _load_test_generator("generators.test.Blank")
    g.supports_multiple_generations = supports_multiple_generations
    g._call_model = (
        lambda prompt, generations_this_call=1: ["a raw string, not a Message"]
        * generations_this_call
    )

    with pytest.raises(AssertionError, match="must each be a Message or None"):
        g.generate(CONVERSATION, generations_this_call)


@pytest.mark.parametrize(
    "generations_this_call,supports_multiple_generations",
    [(1, False), (3, True)],
    ids=["single", "multi-gen"],
)
def test_generate_rejects_wrong_length_call_model_output(
    generations_this_call, supports_multiple_generations
):
    """generate() must reject a _call_model that returns the wrong number of
    items for the requested generation count."""
    g = _load_test_generator("generators.test.Blank")
    g.supports_multiple_generations = supports_multiple_generations
    g._call_model = lambda prompt, generations_this_call=1: [Message("")] * (
        generations_this_call + 1
    )

    with pytest.raises(AssertionError, match="must return"):
        g.generate(CONVERSATION, generations_this_call)


@pytest.mark.parametrize(
    "generations_this_call,supports_multiple_generations",
    [(1, False), (3, True), (3, False)],
    ids=["single", "multi-gen", "serial-multi"],
)
def test_generate_accepts_well_formed_call_model_output(
    generations_this_call, supports_multiple_generations
):
    """A _call_model returning the right count of Message/None items passes on
    every path."""
    g = _load_test_generator("generators.test.Blank")
    g.supports_multiple_generations = supports_multiple_generations
    g._call_model = lambda prompt, generations_this_call=1: (
        [Message("ok"), None][:1] * generations_this_call
    )

    result = g.generate(CONVERSATION, generations_this_call)
    assert len(result) == generations_this_call
    assert all(isinstance(item, Message) or item is None for item in result)
