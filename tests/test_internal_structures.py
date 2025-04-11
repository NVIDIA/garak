# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Iterable
import importlib
import tempfile

import pytest

import garak._config
import garak._plugins
import garak.attempt
import garak.evaluators.base
import garak.generators.test

# probes should be able to return a generator of attempts
# -> probes.base.Probe._execute_all (1) should be able to consume a generator of attempts
# generators should be able to return a generator of outputs
# -> attempts (2) should be able to consume a generator of outputs
# detectors should be able to return generators of results
# -> evaluators (3) should be able to consume generators of results --> enforced in harness; cast to list, multiple consumption


@pytest.fixture(autouse=True)
def _config_loaded():
    importlib.reload(garak._config)
    garak._config.load_base_config()
    garak._config.plugins.probes["test"]["generations"] = 1
    temp_report_file = tempfile.NamedTemporaryFile(mode="w+")
    garak._config.transient.reportfile = temp_report_file
    garak._config.transient.report_filename = temp_report_file.name
    yield
    temp_report_file.close()


def test_generator_consume_attempt_generator():
    count = 5
    attempts = (garak.attempt.Attempt(prompt=str(i), bcp47="*") for i in range(count))
    p = garak._plugins.load_plugin("probes.test.Blank")
    g = garak._plugins.load_plugin("generators.test.Blank")
    p.generator = g
    results = p._execute_all(attempts)

    assert isinstance(results, Iterable), "_execute_all should return an Iterable"
    result_len = 0
    for _attempt in results:
        assert isinstance(
            _attempt, garak.attempt.Attempt
        ), "_execute_all should return attempts"
        result_len += 1
    assert (
        result_len == count
    ), "there should be the same number of attempts in the passed generator as results returned in _execute_all"


def test_attempt_outputs_can_consume_generator():
    a = garak.attempt.Attempt(prompt="fish", bcp47="*")
    count = 5
    str_iter = ("abc" for _ in range(count))
    a.outputs = str_iter
    outputs_list = list(a.outputs)
    assert (
        len(outputs_list) == count
    ), "attempt.outputs should have same cardinality as probe used to populate it"
    assert len(list(a.outputs)) == len(
        outputs_list
    ), "attempt.outputs should have the same cardinality every time"
