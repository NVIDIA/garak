# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
from garak.attempt import Turn
import garak.generators.base
import garak.generators.test

TEST_GENERATORS = [
    a
    for a, b in garak._plugins.enumerate_plugins("generators")
    if b is True and a.startswith("generators.test")
]


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
