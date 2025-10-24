# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
import garak.cas


def test_get_parent_name():
    assert garak.cas.get_parent_name("C") == ""
    assert garak.cas.get_parent_name("C001") == "C"
    assert garak.cas.get_parent_name("C001sub") == "C001"

    with pytest.raises(ValueError):
        garak.cas.get_parent_name("")
    with pytest.raises(ValueError):
        garak.cas.get_parent_name("long policy name")
    with pytest.raises(ValueError):
        garak.cas.get_parent_name("A000xxxA000xxx")
    with pytest.raises(ValueError):
        garak.cas.get_parent_name("Axxx")
    with pytest.raises(ValueError):
        garak.cas.get_parent_name("A00xxxx")


def test_default_policy_autoload():
    # load and validate default policy
    p = garak.cas.Policy()


def test_policy_propagate():
    p = garak.cas.Policy(autoload=False)
    p.points["A"] = None
    p.points["A000"] = True
    p.propagate_up()
    assert (
        p.points["A"] == True
    ), "propagate_up should propagate policy up over undef (None) points"


def test_default_policy_valid():
    assert (
        garak.cas._load_trait_descriptions() != dict()
    ), "default policy typology should be valid and populated"


def test_is_permitted():
    p = garak.cas.Policy(autoload=False)
    p.points["A"] = True
    p.points["A000"] = None
    assert (
        p.is_permitted("A000") == True
    ), "parent perms should override unset child ones"
