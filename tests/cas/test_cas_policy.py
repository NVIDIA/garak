# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

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


def test_settree():
    p = garak.cas.Policy(autoload=False)
    p.points["C"] = None
    p.points["C001"] = None
    p.points["C001one"] = None
    p.points["C002"] = None
    p.points["T"] = None
    p.settree("C001", True)
    assert p.points["C001"] is True, "the named point should be set"
    assert p.points["C001one"] is True, "sub-points of C001 should be set too"
    assert p.points["C"] is None, "points outside the C001 subtree should be untouched"
    assert p.points["C002"] is None, "sibling points of C001 should be untouched"
    assert p.points["T"] is None, "unrelated points should be untouched"


def test_settree_keeps_sibling_leaves():
    # T010id and T010idother are both leaves under T010, so plain string
    # prefix matching on "T010id" would sweep up the sibling as well
    p = garak.cas.Policy(autoload=False)
    p.points["T010"] = None
    p.points["T010id"] = None
    p.points["T010idother"] = None
    p.points["T010license"] = None
    p.settree("T010id", True)
    assert p.points["T010id"] is True, "the named leaf should be set"
    assert p.points["T010idother"] is None, "the sibling leaf should be untouched"
    assert p.points["T010license"] is None, "other children of T010 should be untouched"
    assert p.points["T010"] is None, "the parent point should be untouched"
