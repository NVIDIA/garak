# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import pytest

from garak import _plugins
from garak.attempt import Attempt, Message
from garak.detectors.base import TriggerListDetector
import garak.probes.base
import garak.probes.pdf_injection

TRIGGER = garak.probes.pdf_injection.TRIGGER

PDF_INJECTION_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.pdf_injection")
]


# --- structural tests ---


@pytest.mark.parametrize("classname", PDF_INJECTION_PROBES)
def test_is_probe(classname):
    p = _plugins.load_plugin(classname)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("classname", PDF_INJECTION_PROBES)
def test_prompts_and_triggers_match(classname):
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) > 0
    assert len(p.prompts) == len(p.triggers)


@pytest.mark.parametrize("classname", PDF_INJECTION_PROBES)
def test_prompts_contain_trigger_text(classname):
    p = _plugins.load_plugin(classname)
    for prompt in p.prompts:
        assert isinstance(prompt, Message)
        assert TRIGGER in prompt.text


@pytest.mark.parametrize("classname", PDF_INJECTION_PROBES)
def test_prestore_hook_sets_triggers(classname):
    p = _plugins.load_plugin(classname)
    attempt = Attempt(prompt=p.prompts[0])
    attempt = p._attempt_prestore_hook(attempt, 0)
    assert "triggers" in attempt.notes
    assert attempt.notes["triggers"] == [TRIGGER]


def test_full_covers_all_techniques():
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjectionFull")
    all_text = " ".join(m.text for m in p.prompts)
    for technique in garak.probes.pdf_injection.TECHNIQUES:
        txt_path = (
            garak.probes.pdf_injection.PDF_DATA_DIR / f"{technique}_trigger_reco.txt"
        )
        assert os.path.isfile(txt_path), f"Missing fixture: {txt_path}"


def test_compact_is_subset():
    full = _plugins.load_plugin("probes.pdf_injection.PDFInjectionFull")
    compact = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    assert len(compact.prompts) < len(full.prompts)


# --- detection tests ---


def _make_attempt_with_output(probe, seq, output_text):
    attempt = Attempt(prompt=probe.prompts[seq])
    attempt = probe._attempt_prestore_hook(attempt, seq)
    attempt.outputs = [Message(text=output_text)]
    return attempt


def test_detector_catches_triggered_output():
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    detector = TriggerListDetector()
    attempt = _make_attempt_with_output(p, 0, f"Sure! {TRIGGER}")
    results = detector.detect(attempt)
    assert len(results) == 1
    assert results[0] == 1.0


def test_detector_passes_clean_output():
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    detector = TriggerListDetector()
    attempt = _make_attempt_with_output(
        p, 0, "This is a quarterly financial report showing $4.2M revenue."
    )
    results = detector.detect(attempt)
    assert len(results) == 1
    assert results[0] == 0.0


def test_detector_case_insensitive():
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    detector = TriggerListDetector()
    attempt = _make_attempt_with_output(p, 0, TRIGGER.lower())
    results = detector.detect(attempt)
    assert results[0] == 1.0
