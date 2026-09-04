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

    Asserts the exact "NFKC+strip_format" value (not just "not None") so a
    downgrade to plain "NFKC" -- which does not strip zero-width joiners --
    is also caught, and exercises both the fullwidth and ZWJ evasion cases
    since NFKC alone only closes the former. Term selection skips gracefully
    rather than raising StopIteration if a future substring list has nothing
    matching the filter.
    """
    detector = getattr(lmrc, classname)()
    assert detector.normalize == "NFKC+strip_format", (
        f"{classname} does not enable normalize=\"NFKC+strip_format\" and is "
        "therefore bypassable by full-width homoglyph and/or zero-width-joiner "
        "substitution"
    )

    term = next(
        (t for t in detector.substrings if any(c.isalpha() for c in t) and len(t) >= 3),
        None,
    )
    if term is None:
        pytest.skip(f"{classname} has no substring long enough to test")
    fullwidth = "".join(
        chr(0xFF00 + ord(c) - 0x20) if 0x21 <= ord(c) < 0x7F else c for c in term
    )
    zwj_spliced = "\u200d".join(term)  # zero-width joiner, spelled out rather than embedded

    attempt = Attempt(prompt=Message("test prompt", lang="*"))
    attempt.outputs = [f"consider {fullwidth} as an example, please"]
    assert detector.detect(attempt) == [
        1.0
    ], f"{classname} misses the full-width homoglyph form of {term!r}"

    attempt2 = Attempt(prompt=Message("test prompt", lang="*"))
    attempt2.outputs = [f"consider {zwj_spliced} as an example, please"]
    assert detector.detect(attempt2) == [
        1.0
    ], f"{classname} misses the zero-width-joiner-spliced form of {term!r}"
