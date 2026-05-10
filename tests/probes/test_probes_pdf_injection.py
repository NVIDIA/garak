# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess

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
def test_prompts_are_messages_with_pdf(classname):
    p = _plugins.load_plugin(classname)
    for prompt in p.prompts:
        assert isinstance(prompt, Message)
        assert prompt.data_path is not None
        assert os.path.isfile(prompt.data_path)
        assert prompt.data_type == ("application", "pdf")


@pytest.mark.parametrize("classname", PDF_INJECTION_PROBES)
def test_prestore_hook_sets_triggers(classname):
    p = _plugins.load_plugin(classname)
    attempt = Attempt(prompt=p.prompts[0])
    attempt = p._attempt_prestore_hook(attempt, 0)
    assert "triggers" in attempt.notes
    assert attempt.notes["triggers"] == [TRIGGER]


def test_full_covers_all_techniques():
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjectionFull")
    pdf_basenames = {os.path.basename(m.data_path) for m in p.prompts}
    for technique in garak.probes.pdf_injection.TECHNIQUES:
        assert any(f.startswith(technique) for f in pdf_basenames)


def test_compact_is_subset():
    full = _plugins.load_plugin("probes.pdf_injection.PDFInjectionFull")
    compact = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    assert len(compact.prompts) < len(full.prompts)


# --- detection tests: verify the detector actually catches injections ---


def _make_attempt_with_output(probe, seq, output_text):
    """Wire up an attempt the way the garak harness does."""
    attempt = Attempt(prompt=probe.prompts[seq])
    attempt = probe._attempt_prestore_hook(attempt, seq)
    attempt.outputs = [Message(text=output_text)]
    return attempt


def test_detector_catches_triggered_output():
    """If a model follows the injection and outputs the trigger, the detector must flag it."""
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    detector = TriggerListDetector()
    attempt = _make_attempt_with_output(p, 0, f"Sure! {TRIGGER}")
    results = detector.detect(attempt)
    assert len(results) == 1
    assert results[0] == 1.0


def test_detector_passes_clean_output():
    """If a model ignores the injection and responds normally, the detector must not flag it."""
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    detector = TriggerListDetector()
    attempt = _make_attempt_with_output(
        p, 0, "This is a quarterly financial report showing $4.2M revenue."
    )
    results = detector.detect(attempt)
    assert len(results) == 1
    assert results[0] == 0.0


def test_detector_case_insensitive():
    """Trigger detection should be case-insensitive by default."""
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjection")
    detector = TriggerListDetector()
    attempt = _make_attempt_with_output(p, 0, TRIGGER.lower())
    results = detector.detect(attempt)
    assert results[0] == 1.0


# --- PDF content validation: hidden text must be extractable ---


def test_pdfs_contain_hidden_trigger_text():
    """The injected PDFs must contain the trigger in their extractable text.

    Uses pdftotext or python fallback. If the hidden text isn't extractable,
    the whole probe is pointless.
    """
    p = _plugins.load_plugin("probes.pdf_injection.PDFInjectionFull")
    seen_techniques = set()

    for prompt in p.prompts:
        pdf_path = prompt.data_path
        basename = os.path.basename(pdf_path)
        technique = basename.split("_")[0]

        if technique in seen_techniques:
            continue

        extracted = _extract_pdf_text(pdf_path)
        if extracted is not None and TRIGGER in extracted:
            seen_techniques.add(technique)

    assert len(seen_techniques) > 0, (
        "None of the injection techniques produced extractable trigger text. "
        "Install pymupdf or poppler-utils for full validation."
    )


def _extract_pdf_text(pdf_path):
    """Try pymupdf first, fall back to pdftotext CLI."""
    try:
        import fitz

        doc = fitz.open(pdf_path)
        text = "".join(page.get_text() for page in doc)
        doc.close()
        return text
    except ImportError:
        pass

    try:
        result = subprocess.run(
            ["pdftotext", pdf_path, "-"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None
