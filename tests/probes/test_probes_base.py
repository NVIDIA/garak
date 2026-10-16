# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak._config import GarakSubConfig
import garak.probes


class TreeSearchStub(garak.probes.TreeSearchProbe):
    """Concrete TreeSearchProbe that adds no search behaviour, for construction tests"""

    # Configurable resolves config by plugin type and namespace, so this has to
    # look like it lives under garak.probes
    __module__ = "garak.probes.mock"

    lang = "*"
    goal = "exercise tree search construction"
    primary_detector = "always.Passthru"


def _stub_with_strategy(strategy):
    config_root = GarakSubConfig()
    setattr(config_root, "probes", {"mock": {"strategy": strategy}})
    return TreeSearchStub(config_root=config_root)


@pytest.mark.parametrize("strategy", ["breadth_first", "depth_first"])
def test_tree_search_accepts_supported_strategy(strategy):
    probe = _stub_with_strategy(strategy)
    assert (
        probe.strategy == strategy
    ), "a supported tree search strategy should survive construction"


@pytest.mark.parametrize(
    "strategy", ["first", "breadth", "depth", "", "_", ", ", "sideways_first"]
)
def test_tree_search_rejects_unsupported_strategy(strategy):
    # none of these name a branch of the dispatch in TreeSearchProbe.probe, so
    # accepting one leaves current_node unbound once the queue is walked
    with pytest.raises(ValueError, match="Unsupported tree search strategy"):
        _stub_with_strategy(strategy)
