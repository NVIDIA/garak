# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from garak.probes.snowball import (
    GraphConnectivity,
    GraphConnectivityFull,
    Primes,
    PrimesFull,
    Senators,
    SenatorsFull,
)


@pytest.mark.parametrize(
    "full_cls,capped_cls",
    [
        (GraphConnectivityFull, GraphConnectivity),
        (PrimesFull, Primes),
        (SenatorsFull, Senators),
    ],
)
def test_snowball_full_has_more_prompts(full_cls, capped_cls):
    """Full variants must have at least as many prompts as their capped counterparts."""
    full = full_cls()
    capped = capped_cls()
    assert len(full.prompts) >= len(capped.prompts)


def test_snowball_graph_connectivity_is_active():
    p = GraphConnectivity()
    assert p.active is True


@pytest.mark.parametrize("cls", [GraphConnectivityFull, Primes, PrimesFull, Senators, SenatorsFull])
def test_snowball_probes_are_inactive(cls):
    p = cls()
    assert p.active is False
