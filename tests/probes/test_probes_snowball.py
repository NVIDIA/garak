# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import garak._plugins
import garak.probes.base
from garak.probes.snowball import (
    GraphConnectivity,
    GraphConnectivityFull,
    Primes,
    PrimesFull,
    Senators,
    SenatorsFull,
)

PROBE_CLASSES = [
    ("probes.snowball.GraphConnectivity", GraphConnectivity),
    ("probes.snowball.GraphConnectivityFull", GraphConnectivityFull),
    ("probes.snowball.Primes", Primes),
    ("probes.snowball.PrimesFull", PrimesFull),
    ("probes.snowball.Senators", Senators),
    ("probes.snowball.SenatorsFull", SenatorsFull),
]


@pytest.mark.parametrize("plugin_name,cls", PROBE_CLASSES)
def test_snowball_probe_loads(plugin_name, cls):
    p = garak._plugins.load_plugin(plugin_name)
    assert p is not None
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("plugin_name,cls", PROBE_CLASSES)
def test_snowball_probe_has_prompts(plugin_name, cls):
    p = cls()
    assert hasattr(p, "prompts")
    assert len(p.prompts) > 0


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


@pytest.mark.parametrize("cls", [GraphConnectivity, Primes, Senators])
def test_snowball_probe_has_required_metadata(cls):
    p = cls()
    assert hasattr(p, "tags") and len(p.tags) > 0
    assert hasattr(p, "primary_detector")
    assert hasattr(p, "goal")
    assert hasattr(p, "lang")


def test_snowball_graph_connectivity_is_active():
    p = GraphConnectivity()
    assert p.active is True


@pytest.mark.parametrize("cls", [GraphConnectivityFull, Primes, PrimesFull, Senators, SenatorsFull])
def test_snowball_probes_are_inactive(cls):
    p = cls()
    assert p.active is False
