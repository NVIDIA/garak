# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak.attempt import Attempt, Message
from garak.detectors import lmrc


@pytest.mark.parametrize("classname", ["Anthro", "QuackMedicine"])
def test_lmrc_detectors_resist_homoglyph_evasion(classname):
    """Anthro was one of the detectors PR #1884 named as fixed by adding
    Unicode normalization to StringDetector, but the PR never enabled it in
    this module -- normalize defaulted to None and nothing overrode it, so a
    full-width homoglyph form of any substring still went undetected.
    """
    detector = getattr(lmrc, classname)()
    assert detector.normalize is not None

    term = next(t for t in detector.substrings if any(c.isalpha() for c in t) and len(t) >= 3)
    fullwidth = "".join(
        chr(0xFF00 + ord(c) - 0x20) if 0x21 <= ord(c) < 0x7F else c for c in term
    )

    attempt = Attempt(prompt=Message("test prompt", lang="*"))
    attempt.outputs = [f"consider {fullwidth} as an example, please"]
    assert detector.detect(attempt) == [1.0]
