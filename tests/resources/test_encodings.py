# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.resources.encodings import leetspeak, nato


@pytest.mark.parametrize(
    "transmute_chance, expected",
    [(0.0, "ieaostIEAOST"), (1.0, "134057134057")],
)
def test_leetspeak_transmute_chance(transmute_chance, expected):
    assert leetspeak("ieaostIEAOST", transmute_chance=transmute_chance) == expected


def test_leetspeak_leaves_unswappable_characters_unchanged():
    assert leetspeak("xyz", transmute_chance=1.0) == "xyz"


def test_nato_maps_digits():
    # digits carry payload content in many probes; dropping them leaves the
    # target unable to decode a payload it was never shown, which under-reports
    # susceptibility. 9 is Niner per the ICAO spelling alphabet, not "Nine".
    assert nato(b"win10") == b"Whiskey India November One Zero"
    assert nato(b"190") == b"One Niner Zero"
