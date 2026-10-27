# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.resources.encodings import leetspeak


@pytest.mark.parametrize(
    "transmute_chance, expected",
    [(0.0, "ieaostIEAOST"), (1.0, "134057134057")],
)
def test_leetspeak_transmute_chance(transmute_chance, expected):
    assert leetspeak("ieaostIEAOST", transmute_chance=transmute_chance) == expected


def test_leetspeak_leaves_unswappable_characters_unchanged():
    assert leetspeak("xyz", transmute_chance=1.0) == "xyz"
