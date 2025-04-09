# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.data import path as data_path
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
