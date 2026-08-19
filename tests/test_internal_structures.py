# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import json
from typing import List, Tuple
import pytest
import tempfile

from collections.abc import Iterable
from pathlib import Path

import garak._config
import garak._plugins
import garak.analyze.report_digest
import garak.attempt
import garak.buffs.base
import garak.evaluators.base
import garak.harnesses.base

from garak.detectors.mitigation import MitigationBypass

# probes should be able to return a generator of attempts
# -> probes.base.Probe._execute_all (1) should be able to consume a generator of attempts
# generators should be able to return a generator of outputs
# -> attempts (2) should be able to consume a generator of outputs
# detectors should be able to return generators of results
# -> evaluators (3) should be able to consume generators of results --> enforced in harness; cast to list, multiple consumption


@pytest.fixture(autouse=True)
def _config_loaded():
    garak._config.load_base_config()
    garak._config.plugins.probes["test"]["generations"] = 1
    temp_report_file = tempfile.NamedTemporaryFile(
        mode="w+", suffix=".report.jsonl", delete=False
    )
    garak._config.transient.report_filename = temp_report_file.name
    garak._config.transient.reportfile = open(
        garak._config.transient.report_filename, "w", buffering=1, encoding="utf-8"
    )

    yield


def test_generator_consume_attempt_generator():
    count = 5
    attempts = (
        garak.attempt.Attempt(prompt=garak.attempt.Message(text=str(i), lang="*"))
        for i in range(count)
    )
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
    a = garak.attempt.Attempt(prompt=garak.attempt.Message(text="fish", lang="*"))
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


def test_evaluator_detector_naming(mitigation_outputs: Tuple[List[str], List[str]]):
    COMPLYING_OUTPUTS, REFUSAL_OUTPUTS = mitigation_outputs

    d = MitigationBypass()
    attempt = garak.attempt.Attempt(
        prompt=garak.attempt.Message(
            text="testing prompt", lang=d.lang_spec.split(",")[0]
        ),
    )
    attempt.outputs = COMPLYING_OUTPUTS + REFUSAL_OUTPUTS

    detector_probe_name = d.detectorname.replace("garak.detectors.", "")

    attempt.detector_results[detector_probe_name] = d.detect(attempt)
    attempt.probe_classname = detector_probe_name
    attempts = [attempt]

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate(attempts=attempts)

    report_filename_path = Path(garak._config.transient.report_filename)
    assert report_filename_path.exists()

    report_json = [
        json.loads(line) for line in report_filename_path.read_text().split("\n")[:-1]
    ]
    assert len(report_json) > 0
    for report in report_json:
        detector = report.get("detector", None)
        if detector:
            assert not detector.startswith("detector")


def _read_report_records(entry_type=None):
    report_filename_path = Path(garak._config.transient.report_filename)
    assert report_filename_path.exists()
    records = [
        json.loads(line) for line in report_filename_path.read_text().splitlines()
    ]
    if entry_type is None:
        return records
    return [record for record in records if record["entry_type"] == entry_type]


def _merge_plugin_cache_records(records):
    plugin_cache = {}
    for record in records:
        for category, entries in record["plugin_cache"].items():
            if category == "version":
                plugin_cache["version"] = entries
                continue
            plugin_cache.setdefault(category, {}).update(entries)
    return plugin_cache


def test_harness_emits_plugin_cache_entries_for_loaded_plugins(mocker, monkeypatch):
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    harness = garak.harnesses.base.Harness()
    model = garak._plugins.load_plugin("generators.test.Blank")
    probe = garak._plugins.load_plugin("probes.test.Blank")
    detector = garak._plugins.load_plugin("detectors.always.Pass")
    monkeypatch.setattr(
        garak._config.buffmanager,
        "buffs",
        [garak.buffs.base.Buff()],
    )

    harness.run(model, [probe], [detector], mocker.Mock())

    merged = _merge_plugin_cache_records(_read_report_records("plugin_cache"))
    assert merged["version"] == garak.__version__
    assert "harnesses.base.Harness" in merged["harnesses"]
    assert "generators.test.Blank" in merged["generators"]
    assert "probes.test.Blank" in merged["probes"]
    assert "detectors.always.Pass" in merged["detectors"]
    assert "buffs.base.Buff" in merged["buffs"]
    assert "probes.test.Test" not in merged.get("probes", {})


def test_digest_uses_harness_emitted_plugin_cache(mocker, tmp_path):
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    harness = garak.harnesses.base.Harness()
    model = garak._plugins.load_plugin("generators.test.Blank")
    probe = garak._plugins.load_plugin("probes.test.Blank")
    detector = garak._plugins.load_plugin("detectors.always.Pass")
    evaluator = garak.evaluators.base.Evaluator()

    harness.run(model, [probe], [detector], evaluator)
    garak._config.transient.reportfile.flush()
    report_path = tmp_path / "harness.report.jsonl"
    records = [
        {
            "entry_type": "start_run setup",
            "plugins.probe_spec": "test.Blank",
            "plugins.target_type": "test",
            "plugins.target_name": "Blank",
        },
        {
            "entry_type": "init",
            "garak_version": garak._config.version,
            "start_time": "2026-01-01T00:00:00",
            "run": "test-run",
        },
        *_read_report_records(),
    ]
    with report_path.open("w", encoding="utf-8") as reportfile:
        for record in records:
            reportfile.write(json.dumps(record, ensure_ascii=False) + "\n")
    mocker.patch.object(
        garak._plugins.PluginCache,
        "plugin_info",
        side_effect=AssertionError("live cache should not be used"),
    )

    digest = garak.analyze.report_digest.build_digest(str(report_path))

    assert digest["meta"]["plugin_cache_source"] == garak.__version__
