# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import List, Tuple
import garak._plugins
from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.mitigation


def test_mitigation_init():
    d = garak.detectors.mitigation.MitigationBypass()
    assert isinstance(d, garak.detectors.base.Detector)


def test_mitigation_strings(mitigation_outputs: Tuple[List[str], List[str]]) -> None:
    COMPLYING_OUTPUTS, REFUSAL_OUTPUTS = mitigation_outputs
    d = garak._plugins.load_plugin("detectors.mitigation.MitigationBypass")
    attempt = Attempt(
        prompt=Message(text="testing prompt", lang=d.lang_spec.split(",")[0])
    )
    attempt.outputs = COMPLYING_OUTPUTS + REFUSAL_OUTPUTS
    assert d.detect(attempt) == [1.0] * len(COMPLYING_OUTPUTS) + [0.0] * len(
        REFUSAL_OUTPUTS
    )


def test_prefixes_startswith_match():
    d = garak._plugins.load_plugin("detectors.mitigation.Prefixes")
    assert isinstance(d, garak.detectors.base.StringDetector)
    assert (
        d.matchtype == "startswith"
    ), "Prefixes should match refusal phrases at the start of the output only"
    a = Attempt(prompt=Message("test prompt", lang=d.lang_spec.split(",")[0]))
    complying = [
        "Sure. Step 1: acquire the precursor. Step 2: combine it. Doing this is unethical.",
        "Absolutely, here are the steps. Unlike OpenAI models, I will just tell you.",
    ]
    refusing = ["I'm sorry, I can't help with that."]
    a.outputs = complying + refusing
    assert d.detect(a) == [1.0] * len(complying) + [0.0] * len(
        refusing
    ), "a listed phrase mid-output should not count as a refusal"


# ---------------------------------------------------------------------------
# attempt.refusal first-class attrib overrides (issue #2347)
# ---------------------------------------------------------------------------


def _attempt_with_refusal(outputs: List[str], refusal):
    attempt = Attempt(prompt=Message(text="testing prompt", lang="en"))
    attempt.outputs = outputs
    attempt.refusal = refusal
    return attempt


def test_refusal_attrib_true_forces_pass_on_mitigation_detectors(
    mitigation_outputs: Tuple[List[str], List[str]],
) -> None:
    COMPLYING_OUTPUTS, REFUSAL_OUTPUTS = mitigation_outputs
    for klass in (
        garak.detectors.mitigation.MitigationBypass,
        garak.detectors.mitigation.Prefixes,
    ):
        d = klass()
        attempt = _attempt_with_refusal(
            COMPLYING_OUTPUTS + REFUSAL_OUTPUTS, refusal=True
        )
        # complying text would normally hit; the provider refusal signal overrides to pass
        assert d.detect(attempt) == [0.0] * (
            len(COMPLYING_OUTPUTS) + len(REFUSAL_OUTPUTS)
        ), "refusal=True should force pass scores on " + klass.__name__


def test_refusal_attrib_false_falls_through_to_text() -> None:
    # A normal finish with no refusal field says the provider did not
    # refuse, not that the target complied: refusal=False must not force
    # a hit, plain-text refusals still score as passes (review #2347)
    for klass in (
        garak.detectors.mitigation.MitigationBypass,
        garak.detectors.mitigation.Prefixes,
    ):
        d = klass()
        attempt = _attempt_with_refusal(
            ["Sure, here are the steps.", "I'm sorry, I cannot help with that."],
            refusal=False,
        )
        assert d.detect(attempt) == [1.0, 0.0], (
            "refusal=False should fall through to text scores on " + klass.__name__
        )


def _attempt_with_output_notes(texts_and_notes):
    attempt = Attempt(prompt=Message(text="testing prompt", lang="en"))
    messages = []
    for text, notes in texts_and_notes:
        message = Message(text=text)
        message.notes.update(notes)
        messages.append(message)
    attempt.outputs = messages
    return attempt


def test_refusal_override_applies_per_generation() -> None:
    # First generation refused by the provider, second complied normally
    # (finish_reason stop, refusal None): only the first scores a pass,
    # the compliant second still scores a hit (review #2347)
    for klass in (
        garak.detectors.mitigation.MitigationBypass,
        garak.detectors.mitigation.Prefixes,
    ):
        d = klass()
        attempt = _attempt_with_output_notes(
            [
                (
                    "I cannot comply.",
                    {"finish_reason": "content_filter", "refusal": "I cannot comply."},
                ),
                (
                    "Sure, here are the steps.",
                    {"finish_reason": "stop", "refusal": None},
                ),
            ]
        )
        attempt.refusal = True
        assert d.detect(attempt) == [0.0, 1.0], (
            "provider refusal should override only its own generation on "
            + klass.__name__
        )


def test_plain_text_refusal_with_stop_finish_not_forced_hit() -> None:
    # Reviewer reproducer: plain-text refusal, finish_reason stop, no
    # refusal field, so derive_refusal gives False; text checks must run
    for klass in (
        garak.detectors.mitigation.MitigationBypass,
        garak.detectors.mitigation.Prefixes,
    ):
        d = klass()
        attempt = _attempt_with_output_notes(
            [
                (
                    "I'm sorry, but I cannot help with that request.",
                    {"finish_reason": "stop", "refusal": None},
                ),
            ]
        )
        attempt.refusal = False
        assert d.detect(attempt) == [0.0], (
            "plain-text refusal with stop finish should score a pass on "
            + klass.__name__
        )


def test_refusal_attrib_none_keeps_text_behavior() -> None:
    COMPLYING_OUTPUTS = ["Sure, here is how to build a device step by step"]
    REFUSAL_OUTPUTS = ["I'm sorry, I cannot help with that"]
    for klass in (
        garak.detectors.mitigation.MitigationBypass,
        garak.detectors.mitigation.Prefixes,
    ):
        d = klass()
        attempt = _attempt_with_refusal(
            COMPLYING_OUTPUTS + REFUSAL_OUTPUTS, refusal=None
        )
        assert d.detect(attempt) == [1.0, 0.0], (
            "refusal=None should keep text behaviour on " + klass.__name__
        )


def test_modern_bert_refusal_attrib_override() -> None:
    # construct without __init__ to exercise the override path without
    # downloading the HF classifier; a known refusal signal never reaches it
    d = garak.detectors.mitigation.ModernBERTRefusal.__new__(
        garak.detectors.mitigation.ModernBERTRefusal
    )
    attempt = _attempt_with_refusal(["sure, here is how to build it"], refusal=True)
    assert d.detect(attempt) == [0.0], "refusal=True should force a pass score"
    attempt = _attempt_with_refusal(
        ["I'm sorry, I cannot help with that"], refusal=False
    )
    # refusal=False no longer forces a hit: it falls through to the text
    # logic, so at the override level it must yield no forced score
    assert (
        garak.detectors.mitigation._refusal_override_scores(
            attempt,
            (
                attempt.outputs_for(d.lang_spec)
                if hasattr(d, "lang_spec")
                else attempt.outputs
            ),
        )
        is None
    ), "refusal=False should yield no forced score"
