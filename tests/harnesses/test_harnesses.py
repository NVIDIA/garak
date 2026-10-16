# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import tempfile

import pytest

from garak import _plugins, _config

import garak.buffs.base
import garak.harnesses.base
import garak.probes.base

HARNESSES = [
    classname for (classname, active) in _plugins.enumerate_plugins("harnesses")
]


@pytest.fixture(autouse=True)
def _config_loaded():
    """Load base config + a temp report file so harness.run() can write."""
    _config.load_base_config()
    _config.plugins.probes["test"]["generations"] = 1
    temp_report_file = tempfile.NamedTemporaryFile(
        mode="w+", suffix=".report.jsonl", delete=False
    )
    _config.transient.report_filename = temp_report_file.name
    _config.transient.reportfile = open(
        _config.transient.report_filename, "w", buffering=1, encoding="utf-8"
    )

    yield


@pytest.mark.parametrize("classname", HARNESSES)
def test_harness_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # any parameter that has a default must be supported
    unsupported_defaults = []
    if c._supported_params is not None:
        if hasattr(c, "DEFAULT_PARAMS"):
            for k, _ in c.DEFAULT_PARAMS.items():
                if k not in c._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


def test_harness_modality_match():
    t = {"text"}
    ti = {"text", "image"}
    tv = {"text", "vision"}
    tvi = {"text", "vision", "image"}

    # probe, generator
    assert garak.harnesses.base._modality_match(t, t, True) is True
    assert garak.harnesses.base._modality_match(ti, ti, True) is True
    assert garak.harnesses.base._modality_match(t, tv, True) is False
    assert garak.harnesses.base._modality_match(ti, t, True) is False

    # when strict is false, generator must support all probe modalities, but can also support more
    assert garak.harnesses.base._modality_match(t, t, False) is True
    assert garak.harnesses.base._modality_match(ti, t, False) is False
    assert garak.harnesses.base._modality_match(t, tvi, False) is True
    assert garak.harnesses.base._modality_match(ti, tvi, False) is True
    assert garak.harnesses.base._modality_match(t, ti, False) is True


def test_harness_detector_progress_shows_probe_name(mocker, monkeypatch):
    """Detector progress bar must show which probe is being processed (#324)."""
    mocker.patch("garak.harnesses.base._initialize_runtime_services")

    captured_descriptions = []
    real_tqdm = garak.harnesses.base.tqdm.tqdm

    def capturing_tqdm(*args, **kwargs):
        bar = real_tqdm(*args, **kwargs)
        original_set_description = bar.set_description

        def set_description(desc, *a, **kw):
            captured_descriptions.append(desc)
            return original_set_description(desc, *a, **kw)

        bar.set_description = set_description
        return bar

    monkeypatch.setattr(garak.harnesses.base.tqdm, "tqdm", capturing_tqdm)

    harness = garak.harnesses.base.Harness()
    model = _plugins.load_plugin("generators.test.Blank")
    probe = _plugins.load_plugin("probes.test.Blank")
    detector = _plugins.load_plugin("detectors.always.Pass")
    monkeypatch.setattr(
        _config.buffmanager,
        "buffs",
        [garak.buffs.base.Buff()],
    )

    harness.run(model, [probe], [detector], mocker.Mock())

    assert captured_descriptions, "detector progress bar should have a description"
    assert any(
        "test.Blank" in desc and "always.Pass" in desc
        for desc in captured_descriptions
    ), "detector progress description should include probe and detector names"


def test_harness_unscorable_outputs_do_not_halt_probe_queue(mocker, monkeypatch):
    """A detector that cannot score one probe's outputs must not strand the rest of the queue."""
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    monkeypatch.setattr(
        _config.buffmanager,
        "buffs",
        [garak.buffs.base.Buff()],
    )

    harness = garak.harnesses.base.Harness()
    model = _plugins.load_plugin("generators.test.Blank")
    probes = [
        _plugins.load_plugin("probes.test.Blank"),
        _plugins.load_plugin("probes.test.Test"),
    ]
    # only scores local filenames, so neither probe's text outputs are scorable
    detector = _plugins.load_plugin("detectors.fileformats.FileIsPickled")
    evaluator = mocker.Mock()

    harness.run(model, probes, [detector], evaluator)

    evaluated_probes = {
        attempt.probe_classname
        for call in evaluator.evaluate.call_args_list
        for attempt in call.args[0]
    }
    assert evaluated_probes == {
        "test.Blank",
        "test.Test",
    }, "every queued probe should reach the evaluator when a detector cannot score its outputs"


@pytest.mark.parametrize("intent", [None, ""])
def test_harness_does_not_resolve_falsy_intent(mocker, intent):
    """Falsy attempt intents are warned about and never sent to intentservice."""
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    mocker.patch("garak.harnesses.base._emit_plugin_cache_entry")
    get_detectors = mocker.patch("garak.services.intentservice.get_detectors")

    harness = garak.harnesses.base.Harness()
    mocker.patch.object(harness, "_start_run_hook")
    mocker.patch.object(harness, "_end_run_hook")

    model = mocker.Mock()
    model.modality = {"in": {"text"}}

    probe = mocker.Mock(spec=garak.probes.base.IntentProbe)
    probe.probename = "garak.probes.test.EmptyIntent"
    probe.modality = {"in": {"text"}}

    attempt = mocker.Mock()
    attempt.intent = intent
    attempt.uuid = "empty-intent-attempt"
    attempt.seq = 0
    attempt.as_dict.return_value = {}
    probe.probe.return_value = [attempt]

    detector = mocker.Mock()
    detector.detectorname = "garak.detectors.always.Pass"

    harness.run(model, [probe], [detector], mocker.Mock())

    get_detectors.assert_not_called()


def test_harness_skips_falsy_intent_when_valid_intent_is_present(mocker):
    """An invalid attempt must not break detector selection for valid attempts."""
    mocker.patch("garak.harnesses.base._initialize_runtime_services")
    mocker.patch("garak.harnesses.base._emit_plugin_cache_entry")
    get_detectors = mocker.patch(
        "garak.services.intentservice.get_detectors",
        return_value=["always.Pass"],
    )

    harness = garak.harnesses.base.Harness()
    mocker.patch.object(harness, "_start_run_hook")
    mocker.patch.object(harness, "_end_run_hook")
    run_detector = mocker.patch.object(harness, "_run_detector")

    model = mocker.Mock()
    model.modality = {"in": {"text"}}

    probe = mocker.Mock(spec=garak.probes.base.IntentProbe)
    probe.probename = "garak.probes.test.MixedIntent"
    probe.modality = {"in": {"text"}}

    invalid_attempt = mocker.Mock()
    invalid_attempt.intent = None
    invalid_attempt.uuid = "empty-intent-attempt"
    invalid_attempt.seq = 0
    invalid_attempt.as_dict.return_value = {}

    valid_attempt = mocker.Mock()
    valid_attempt.intent = "T009ignore"
    valid_attempt.uuid = "valid-intent-attempt"
    valid_attempt.seq = 1
    valid_attempt.as_dict.return_value = {}

    probe.probe.return_value = [invalid_attempt, valid_attempt]

    detector = mocker.Mock()
    detector.detectorname = "garak.detectors.always.Pass"

    resolved_detector = mocker.Mock()
    resolved_detector.detectorname = "garak.detectors.always.Pass"
    mocker.patch(
        "garak.harnesses.base._plugins.load_plugin",
        return_value=resolved_detector,
    )

    harness.run(model, [probe], [detector], mocker.Mock())

    get_detectors.assert_called_once_with("T009ignore")
    run_detector.assert_called_once_with([valid_attempt], resolved_detector)
