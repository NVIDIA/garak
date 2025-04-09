# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.policy


def test_get_parent_name():
    assert garak.policy.get_parent_name("C") == ""
    assert garak.policy.get_parent_name("C001") == "C"
    assert garak.policy.get_parent_name("C001sub") == "C001"

    with pytest.raises(ValueError):
        garak.policy.get_parent_name("")
    with pytest.raises(ValueError):
        garak.policy.get_parent_name("long policy name")
    with pytest.raises(ValueError):
        garak.policy.get_parent_name("A000xxxA000xxx")
    with pytest.raises(ValueError):
        garak.policy.get_parent_name("Axxx")
    with pytest.raises(ValueError):
        garak.policy.get_parent_name("A00xxxx")


def test_default_policy_autoload():
    # load and validate default policy
    p = garak.policy.Policy()


def test_policy_propagate():
    p = garak.policy.Policy(autoload=False)
    p.points["A"] = None
    p.points["A000"] = True
    p.propagate_up()
    assert (
        p.points["A"] == True
    ), "propagate_up should propagate policy up over undef (None) points"


def test_default_policy_valid():
    assert (
        garak.policy._load_trait_descriptions() != dict()
    ), "default policy typology should be valid and populated"


def test_is_permitted():
    p = garak.policy.Policy(autoload=False)
    p.points["A"] = True
    p.points["A000"] = None
    assert (
        p.is_permitted("A000") == True
    ), "parent perms should override unset child ones"


def test_trait_probe_separation():
    trait_probes_set = set(
        garak._plugins.enumerate_plugins(
            category="probes", filter={"trait_probe": True}
        )
    )
    non_trait_probes_set = set(
        garak._plugins.enumerate_plugins(
            category="probes", filter={"trait_probe": False}
        )
    )

    overlap = trait_probes_set.intersection(non_trait_probes_set)
    assert len(trait_probes_set) > 1, "There should be at least one trait probe"
    assert len(non_trait_probes_set) > 1, "There should be at least one non-trait probe"
    assert (
        overlap == set()
    ), f"No probes should come up as both trait and non-trait; got {overlap}"
