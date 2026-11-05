# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for request dispatch in the base generator."""

import pickle
import threading
from unittest.mock import patch

import pytest

from garak.attempt import Conversation, Message, Turn
from garak.generators.base import Generator


class SerialGenerator(Generator):
    """A generator with process-local state created on its first request."""

    parallel_capable = False

    def _call_model(self, prompt, generations_this_call=1):
        if not hasattr(self, "connection"):
            self.connection = threading.Lock()
        return [Message(text=prompt.last_message().text)]


@pytest.mark.parametrize("previously_used", [False, True])
def test_serial_generator_ignores_parallel_requests(previously_used):
    """Serial generators must not enter the pool path, even after first use."""
    generator = SerialGenerator(name="serial test")
    generator.parallel_requests = 2
    generator.max_workers = 2
    prompt = Conversation([Turn("user", Message("hello"))])
    if previously_used:
        assert generator.generate(prompt)[0].text == "hello"
        with pytest.raises(TypeError):
            pickle.dumps(generator)

    with patch("multiprocessing.Pool", side_effect=AssertionError("unexpected pool")):
        with patch.object(
            generator, "_call_model", wraps=generator._call_model
        ) as call:
            outputs = generator.generate(prompt, generations_this_call=3)
            assert call.call_count == 3

    assert [output.text for output in outputs] == ["hello"] * 3


@pytest.mark.parametrize(
    "requests, workers, generations, expected_pool_size",
    [(2, 2, 3, 2), (2, 1, 3, 1), (10, 10, 3, 3)],
)
def test_parallel_generator_still_uses_pool(
    requests, workers, generations, expected_pool_size
):
    """Parallel dispatch retains the request, worker and generation caps."""
    generator = Generator(name="parallel test")
    generator.parallel_requests = requests
    generator.max_workers = workers
    prompt = Conversation([Turn("user", Message("hello"))])
    with patch("multiprocessing.Pool") as pool:
        pool.return_value.imap_unordered.return_value = [
            [Message(text=str(index))] for index in range(generations)
        ]
        outputs = generator.generate(prompt, generations_this_call=generations)
        pool.assert_called_once_with(expected_pool_size)
        pool.return_value.imap_unordered.assert_called_once_with(
            generator._call_model, [prompt] * generations
        )
        pool.return_value.close.assert_called_once_with()
        pool.return_value.join.assert_called_once_with()
    assert [output.text for output in outputs] == [
        str(index) for index in range(generations)
    ]


@pytest.mark.parametrize(
    "parallel_capable, requests, generations",
    [
        (capable, requests, generations)
        for capable in [False, True]
        for requests in [False, None, 0, 1, 2]
        for generations in [0, 1, 3]
        if not (capable and requests == 2 and generations == 3)
    ],
)
def test_base_dispatch_boundaries(parallel_capable, requests, generations):
    """Zero/single requests and disabled parallelism do not create workers."""
    generator = SerialGenerator(name="boundary test")
    generator.parallel_capable = parallel_capable
    generator.parallel_requests = requests
    generator.max_workers = 2
    prompt = Conversation([Turn("user", Message("hello"))])
    with patch("multiprocessing.Pool", side_effect=AssertionError("unexpected pool")):
        with patch.object(
            generator, "_call_model", wraps=generator._call_model
        ) as call:
            outputs = generator.generate(prompt, generations_this_call=generations)
            assert call.call_count == generations
    assert [output.text for output in outputs] == ["hello"] * generations


@pytest.mark.parametrize("parallel_capable", [False, True])
def test_native_multiple_generations_bypasses_pool(parallel_capable):
    """Native batching stays separate from request-level multiprocessing."""
    generator = Generator(name="batch test")
    generator.parallel_capable = parallel_capable
    generator.supports_multiple_generations = True
    generator.parallel_requests = 2
    generator.max_workers = 2
    prompt = Conversation([Turn("user", Message("hello"))])
    with patch("multiprocessing.Pool", side_effect=AssertionError("unexpected pool")):
        with patch.object(
            generator, "_call_model", return_value=[Message(text="hello")] * 3
        ) as call:
            outputs = generator.generate(prompt, generations_this_call=3)
            call.assert_called_once_with(prompt, 3)
    assert [output.text for output in outputs] == ["hello"] * 3
