# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# load default
# load non-existing
# load empty
# lookup absent combo
# calc valid zscore
# calc zscore w/ s.d. 0
# check comment assignment
# check dc assignment

import pytest

import garak.analyze.calibration


def test_instantiate():
    c = garak.analyze.calibration.Calibration()
    assert isinstance(c, garak.analyze.calibration.Calibration)
    assert (
        c.calibration_successfully_loaded == True
    ), "default calibration load should use default data and succeed"
    assert isinstance(c._data, dict)
    assert len(c._data) > 0, "default calibration data should not be empty"
    assert isinstance(c.metadata, dict), "default calibration must have metadata"
    assert (
        len(c.metadata) > 0
    ), "default calibration must have metadata with entries present"


def test_constructor_with_missing_file():
    c = garak.analyze.calibration.Calibration("akshjdfiojavpoij")
    assert c.calibration_successfully_loaded == False
    assert isinstance(c._data, dict)
    assert c._data == {}
    assert c.metadata is None

    c = garak.analyze.calibration.Calibration("")
    assert c.calibration_successfully_loaded == False
    assert isinstance(c._data, dict)
    assert c._data == {}
    assert c.metadata is None


def test_lookup():
    # assumes this particular probe and mitigation remain in the default calibration
    c = garak.analyze.calibration.Calibration()
    z = c.get_z_score("dan", "DanInTheWild", "mitigation", "MitigationBypass", 50)
    assert isinstance(z, float)


def test_lookup_absent_probe_detector():
    c = garak.analyze.calibration.Calibration()
    z = c.get_z_score("a", "b", "c", "d", 50)
    assert z is None


def test_lookup_on_missing_calibration_file():
    c = garak.analyze.calibration.Calibration("alshdfohasdgih")
    z = c.get_z_score("dan", "DanInTheWild", "mitigation", "MitigationBypass", 50)
    assert z is None


def test_calc_z_score():
    c = garak.analyze.calibration.Calibration()
    assert c._calc_z(0.5, 0.1, 0.5) == 0
    assert c._calc_z(0.2, 0.2, 0.0) == -1
    with pytest.raises(ZeroDivisionError) as e:
        c._calc_z(0.4, 0.0, 0.9)


@pytest.mark.parametrize("defcon", [1, 2, 3, 4, 5])
def test_comments_written(defcon):
    assert isinstance(garak.analyze.calibration.RELATIVE_COMMENT[defcon], str)
    assert garak.analyze.calibration.RELATIVE_COMMENT[defcon] != ""


@pytest.mark.parametrize(
    "z", [0.0, -1.0, 1.0, -100000.0, 100000.0, 0.000001, 0.5, -0.5]
)
def test_defcon_comment(z):
    c = garak.analyze.calibration.Calibration()
    defcon, comment = c.defcon_and_comment(z)
    assert isinstance(defcon, int)
    assert isinstance(comment, str)
    assert 1 <= defcon <= 5
    assert comment == garak.analyze.calibration.RELATIVE_COMMENT[defcon]
