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
import garak.attempt
import garak.evaluators.base

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
        json.loads(line)
        for line in report_filename_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if entry_type is None:
        return records
    return [record for record in records if record.get("entry_type") == entry_type]


def _make_attempt(
    probe_name: str,
    intent: str | None,
    detector_name: str,
    detector_results: list[float],
) -> garak.attempt.Attempt:
    attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(text="prompt", lang="*"))
    attempt.probe_classname = probe_name
    attempt.intent = intent
    attempt.outputs = [garak.attempt.Message(text=f"out-{i}", lang="*") for i in range(len(detector_results))]
    attempt.detector_results[detector_name] = detector_results
    return attempt


def test_evaluator_emits_eval_technique_intent(mocker):
    detector_name = "always.Pass"
    technique = "demon:Language:Prompt_injection:Ignore_previous_instructions"
    mocker.patch.object(
        garak.evaluators.base,
        "_probe_technique_tags",
        return_value=[technique],
        create=True,
    )

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate(
        [
            _make_attempt(
                "grandma.GrandmaIntent",
                "S009deep",
                detector_name,
                [0.0, 0.0],
            ),
        ]
    )

    records = _read_report_records("eval_technique_intent")
    assert len(records) == 1
    assert records[0]["technique"] == technique
    assert records[0]["intent"] == "S009deep"
    assert records[0]["detectors_used"] == [detector_name]


def test_evaluator_skips_eval_technique_intent_without_intent(mocker):
    detector_name = "always.Pass"
    mocker.patch.object(
        garak.evaluators.base,
        "_probe_technique_tags",
        return_value=["demon:Language:Prompt_injection:Ignore_previous_instructions"],
        create=True,
    )

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate(
        [
            _make_attempt(
                "grandma.GrandmaIntent",
                None,
                detector_name,
                [0.0, 0.0],
            ),
        ]
    )

    assert not _read_report_records("eval_technique_intent")


def test_evaluator_technique_intent_uses_pair_specific_detector_counts(mocker):
    detector_name = "always.Pass"
    technique = "demon:Language:Prompt_injection:Ignore_previous_instructions"
    mocker.patch.object(
        garak.evaluators.base,
        "_probe_technique_tags",
        return_value=[technique],
        create=True,
    )

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.test = lambda score: score < 0.5
    evaluator.evaluate(
        [
            _make_attempt("grandma.GrandmaIntent", "S009deep", detector_name, [1.0, 1.0]),
            _make_attempt("grandma.GrandmaIntent", "S003productkeys", detector_name, [0.0, 0.0]),
        ]
    )

    records = _read_report_records("eval_technique_intent")
    by_intent = {record["intent"]: record for record in records}

    assert set(by_intent.keys()) == {"S009deep", "S003productkeys"}
    assert by_intent["S009deep"]["score"] == 0.0
    assert by_intent["S003productkeys"]["score"] == 1.0
