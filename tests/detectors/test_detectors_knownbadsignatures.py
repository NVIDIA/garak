# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Detector-unique unit tests for garak/detectors/knownbadsignatures.py.

Generic checks (loading, isinstance, etc.) are covered by
tests/plugins/test_plugin_load.py.
"""

import pytest

from garak.attempt import Attempt, Message
import garak.detectors.knownbadsignatures
from garak.probes.av_spam_scanning import (
    EICAR_SIGNATURE,
    GTUBE_SIGNATURE,
    GTPHISH_SIGNATURE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_attempt(outputs):
    """Build an Attempt with the given list of string outputs (lang=en)."""
    attempt = Attempt(prompt=Message(text="test prompt", lang="en"))
    attempt.outputs = outputs
    return attempt


# The three detectors are structurally identical StringDetectors that differ
# only in which signature they look for, so shared behaviour is parametrized
# across (detector class, its signature) pairs.
DETECTOR_SIGNATURE_PAIRS = [
    pytest.param(garak.detectors.knownbadsignatures.EICAR, EICAR_SIGNATURE, id="eicar"),
    pytest.param(garak.detectors.knownbadsignatures.GTUBE, GTUBE_SIGNATURE, id="gtube"),
    pytest.param(
        garak.detectors.knownbadsignatures.GTphish, GTPHISH_SIGNATURE, id="gtphish"
    ),
]


# ---------------------------------------------------------------------------
# Shared behaviour: signature present / absent / degraded
# ---------------------------------------------------------------------------


class TestKnownBadSignatures:
    """Shared behaviour of the EICAR / GTUBE / GTphish string detectors.

    In garak's convention a *hit* (the signature made it into the model's
    output) corresponds to a score of 1.0, and 0.0 means no hit.
    """

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_signature_alone_is_hit(self, detector_class, signature):
        d = detector_class()
        attempt = _make_attempt([signature])
        assert d.detect(attempt) == [1.0]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_signature_embedded_in_text_is_hit(self, detector_class, signature):
        d = detector_class()
        attempt = _make_attempt(
            [f"Sure! Here is the string you asked for:\n{signature}\nAnything else?"]
        )
        assert d.detect(attempt) == [1.0]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_lowercased_signature_is_hit(self, detector_class, signature):
        # StringDetector defaults to case_sensitive=False, so a model that
        # lowercases the signature on the way out must still be flagged.
        d = detector_class()
        attempt = _make_attempt([signature.lower()])
        assert d.detect(attempt) == [1.0]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_refusal_is_not_hit(self, detector_class, signature):
        d = detector_class()
        attempt = _make_attempt(
            ["I can't repeat that string; it is used to test antivirus software."]
        )
        assert d.detect(attempt) == [0.0]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_truncated_signature_is_not_hit(self, detector_class, signature):
        # Half the signature is not the signature: partial reproduction does
        # not constitute emitting the known-bad string.
        d = detector_class()
        attempt = _make_attempt([signature[: len(signature) // 2]])
        assert d.detect(attempt) == [0.0]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_empty_output_is_not_hit(self, detector_class, signature):
        d = detector_class()
        attempt = _make_attempt([""])
        assert d.detect(attempt) == [0.0]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_none_output_returns_none(self, detector_class, signature):
        """A None Message in outputs should produce a None result (inconclusive)."""
        d = detector_class()
        attempt = _make_attempt(["placeholder"])
        # Replace the last assistant turn content with a Message whose text is None
        for conv in attempt.conversations:
            for turn in conv.turns:
                if turn.role == "assistant":
                    turn.content = Message(text=None, lang="en")
        assert d.detect(attempt) == [None]

    @pytest.mark.parametrize("detector_class,signature", DETECTOR_SIGNATURE_PAIRS)
    def test_multiple_outputs_mixed(self, detector_class, signature):
        d = detector_class()
        attempt = _make_attempt(
            [
                signature,
                "I won't output that.",
                f'print("{signature}")',
            ]
        )
        assert d.detect(attempt) == [1.0, 0.0, 1.0]


# ---------------------------------------------------------------------------
# Distinctness: each detector fires only on its own signature
# ---------------------------------------------------------------------------


class TestSignaturesAreDistinct:
    """A detector must not fire on the other probes' signatures, even though
    GTUBE and GTphish share a common prefix."""

    @pytest.mark.parametrize(
        "detector_class,other_signature",
        [
            pytest.param(
                garak.detectors.knownbadsignatures.EICAR,
                GTUBE_SIGNATURE,
                id="eicar_vs_gtube",
            ),
            pytest.param(
                garak.detectors.knownbadsignatures.GTUBE,
                GTPHISH_SIGNATURE,
                id="gtube_vs_gtphish",
            ),
            pytest.param(
                garak.detectors.knownbadsignatures.GTphish,
                GTUBE_SIGNATURE,
                id="gtphish_vs_gtube",
            ),
            pytest.param(
                garak.detectors.knownbadsignatures.GTphish,
                EICAR_SIGNATURE,
                id="gtphish_vs_eicar",
            ),
        ],
    )
    def test_other_signature_is_not_hit(self, detector_class, other_signature):
        d = detector_class()
        attempt = _make_attempt([other_signature])
        assert d.detect(attempt) == [0.0]
