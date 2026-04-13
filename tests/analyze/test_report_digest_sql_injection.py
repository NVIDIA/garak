# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for parameterized SQL queries in report_digest.

Ensures that SQL metacharacters in probe/detector/group values do not
cause query failures or unintended behavior (CWE-89).
"""

import pytest

from garak.analyze.report_digest import (
    _init_populate_result_db,
    _get_group_aggregate_score,
    _get_probe_result_summaries,
    _get_detectors_info,
    _close_result_db,
)

ADVERSARIAL_PAYLOADS = [
    "x' OR 1=1 --",
    "'; DROP TABLE results; --",
    'Robert"); DROP TABLE results;--',
    "probe\\'group",
    'value with "double quotes"',
    "semi;colon",
]


def _make_eval(probe_module, probe_class, detector, passed=5, total=10):
    """Build a minimal eval record matching the format _init_populate_result_db expects."""
    return {
        "probe": f"probes.{probe_module}.{probe_class}",
        "detector": f"detector.{detector}",
        "passed": passed,
        "total_evaluated": total,
    }


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_insert_with_adversarial_probe_module(payload):
    """INSERT should succeed when probe_module contains SQL metacharacters."""
    evals = [_make_eval(payload, "SafeClass", "safe.Det")]
    conn, cursor = _init_populate_result_db(evals)
    try:
        rows = cursor.execute("select count(*) from results").fetchone()
        assert rows[0] == 1
    finally:
        _close_result_db(conn)


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_insert_with_adversarial_detector(payload):
    """INSERT should succeed when detector contains SQL metacharacters."""
    evals = [_make_eval("safe_mod", "SafeClass", payload)]
    conn, cursor = _init_populate_result_db(evals)
    try:
        rows = cursor.execute("select count(*) from results").fetchone()
        assert rows[0] == 1
    finally:
        _close_result_db(conn)


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_get_group_aggregate_score_with_adversarial_group(payload):
    """SELECT by probe_group should return correct results for adversarial group names."""
    evals = [_make_eval(payload, "TestClass", "det.Det", passed=7, total=10)]
    conn, cursor = _init_populate_result_db(evals)
    try:
        score, unknown = _get_group_aggregate_score(cursor, payload, "mean")
        assert score == pytest.approx(0.7)
        assert not unknown
    finally:
        _close_result_db(conn)


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_get_probe_result_summaries_with_adversarial_group(payload):
    """Probe result summary query should handle adversarial probe_group values."""
    evals = [_make_eval(payload, "TestClass", "det.Det", passed=3, total=10)]
    conn, cursor = _init_populate_result_db(evals)
    try:
        results = _get_probe_result_summaries(cursor, payload)
        assert len(results) == 1
        assert results[0][0] == payload  # probe_module
        assert results[0][1] == "TestClass"  # probe_class
    finally:
        _close_result_db(conn)


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_get_detectors_info_with_adversarial_values(payload):
    """Detector info query should handle adversarial probe_group and probe_class."""
    evals = [_make_eval(payload, payload, f"det.{payload}", passed=4, total=10)]
    conn, cursor = _init_populate_result_db(evals)
    try:
        results = _get_detectors_info(cursor, payload, payload)
        assert len(results) == 1
        assert results[0]["detector"] == f"det.{payload}"  # detector name
        assert results[0]["absolute_score"] == pytest.approx(0.4)  # score
    finally:
        _close_result_db(conn)
