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
import garak.probes.base

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
    attempt.probe_classname = "test.Blank"
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


def _score_attempt(attempt):
    attempt.outputs = [garak.attempt.Message("output")]
    attempt.detector_results["always.Fail"] = [0.0]
    return attempt


def _scored_attempt(probe_name):
    attempt = garak.attempt.Attempt(
        prompt=garak.attempt.Message("prompt", lang="*"),
    )
    attempt.probe_classname = probe_name
    return _score_attempt(attempt)


def test_probe_mint_attempt_with_hook_override():
    class OverrideHookProbe(garak.probes.base.Probe):
        lang = "en"
        tags = ["demon:Language:Code_and_encode:Token"]

        def _attempt_prestore_hook(self, attempt, seq):
            attempt.notes["hook_ran"] = True
            return attempt

    attempt = OverrideHookProbe()._mint_attempt("prompt", seq=0)

    assert attempt.notes["hook_ran"] is True


def test_probe_technique_demon_tags_filters(mocker):
    plugin_info = mocker.patch.object(
        garak._plugins.PluginCache,
        "plugin_info",
        return_value={
            "tags": [
                "owasp:llm01",
                "demon:Fictionalizing:Roleplaying:User_persona",
                "demon:Language:Prompt_injection:Ignore_previous_instructions",
            ]
        },
    )

    assert set(garak.evaluators.base._probe_demon_tags("grandma.GrandmaIntent")) == {
        "demon:Fictionalizing:Roleplaying:User_persona",
        "demon:Language:Prompt_injection:Ignore_previous_instructions",
    }
    plugin_info.assert_called_once_with("probes.grandma.GrandmaIntent")


def test_probe_technique_demon_tags_normalizes_prefixed_probe_name(mocker):
    plugin_info = mocker.patch.object(
        garak._plugins.PluginCache,
        "plugin_info",
        return_value={"tags": ["demon:Fictionalizing:Roleplaying:User_persona"]},
    )

    assert garak.evaluators.base._probe_demon_tags("probes.grandma.GrandmaIntent") == [
        "demon:Fictionalizing:Roleplaying:User_persona"
    ]
    plugin_info.assert_called_once_with("probes.grandma.GrandmaIntent")


def test_probe_technique_demon_tags_returns_empty_list_without_demon_tags(mocker):
    mocker.patch.object(
        garak._plugins.PluginCache,
        "plugin_info",
        return_value={"tags": ["owasp:llm01"]},
    )

    assert garak.evaluators.base._probe_demon_tags("grandma.GrandmaIntent") == []


def test_probe_technique_demon_tags_requires_tags_metadata(mocker):
    mocker.patch.object(
        garak._plugins.PluginCache,
        "plugin_info",
        return_value={},
    )

    with pytest.raises(KeyError):
        garak.evaluators.base._probe_demon_tags("grandma.GrandmaIntent")


def test_probe_technique_demon_tags_rejects_non_string_tags(mocker):
    mocker.patch.object(
        garak._plugins.PluginCache,
        "plugin_info",
        return_value={"tags": ["owasp:llm01", 1]},
    )

    with pytest.raises(TypeError):
        garak.evaluators.base._probe_demon_tags("grandma.GrandmaIntent")


def test_evaluator_emits_eval_technique():
    probe_name = "grandma.GrandmaIntent"
    expected_tags = [
        tag
        for tag in garak._plugins.PluginCache.plugin_info(f"probes.{probe_name}")[
            "tags"
        ]
        if tag.startswith("demon:")
    ]

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate([_scored_attempt(probe_name)])

    technique_records = _read_report_records("eval_technique")

    assert {record["technique"] for record in technique_records} == set(expected_tags)
    assert all(record["probe"] == probe_name for record in technique_records)


def test_evaluator_skips_eval_technique_for_empty_tags():
    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate([_scored_attempt("test.Blank")])

    report_json = _read_report_records()

    assert any(record["entry_type"] == "eval" for record in report_json)
    assert not any(record["entry_type"] == "eval_technique" for record in report_json)


def test_report_attempt_rows_omit_technique_metadata():
    attempt = _scored_attempt("grandma.GrandmaIntent")
    garak._config.transient.reportfile.write(
        json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n"
    )
    attempt.status = garak.attempt.ATTEMPT_COMPLETE
    garak._config.transient.reportfile.write(
        json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n"
    )

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate([attempt])

    report_json = _read_report_records()
    attempt_records = [
        record for record in report_json if record.get("entry_type") == "attempt"
    ]

    assert attempt_records
    removed_field = "technique" + "_tags"
    assert all(removed_field not in record for record in attempt_records)
    assert any(record["entry_type"] == "eval_technique" for record in report_json)


def test_buff_derived_attempt_uses_probe_classname_for_eval_technique():
    source_attempt = garak.attempt.Attempt(
        prompt=garak.attempt.Message("prompt", lang="*"),
        intent="S003productkeys",
    )
    source_attempt.probe_classname = "grandma.GrandmaIntent"

    buff = garak.buffs.base.Buff()
    derived_attempt = buff._derive_new_attempt(source_attempt)
    _score_attempt(derived_attempt)

    assert derived_attempt.intent == "S003productkeys"
    assert derived_attempt.probe_classname == "grandma.GrandmaIntent"

    evaluator = garak.evaluators.base.Evaluator()
    evaluator.evaluate([derived_attempt])

    assert _read_report_records("eval_technique")
