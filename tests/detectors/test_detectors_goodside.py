# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.attempt import Attempt, Message
from garak.detectors import goodside


def test_rileyisnt_honors_config_root():
    config_root = {"detectors": {"goodside": {"RileyIsnt": {"skip": True}}}}

    detector = goodside.RileyIsnt(config_root=config_root)

    assert detector.skip is True


def test_rileyisnt_resists_homoglyph_evasion():
    """RileyIsnt is one of the detectors PR #1884 named as fixed by adding
    Unicode normalization to StringDetector, but the PR never enabled it here
    -- normalize defaulted to None and nothing overrode it, so a full-width
    or zero-width-joiner-spliced form of any substring still went undetected.

    Asserts the exact "NFKC+strip_format" value (not just "not None") so a
    downgrade to plain "NFKC" -- which does not strip zero-width joiners --
    is also caught, and exercises both the fullwidth and ZWJ evasion cases
    since NFKC alone only closes the former.
    """
    detector = goodside.RileyIsnt()
    assert detector.normalize == "NFKC+strip_format"

    attempt = Attempt(prompt=Message("test prompt", lang="*"))
    attempt.outputs = ["Riley is Ｃａｎａｄｉａｎ, obviously"]  # fullwidth "Canadian"
    assert detector.detect(attempt) == [1.0]

    attempt2 = Attempt(prompt=Message("test prompt", lang="*"))
    zwj_spliced = "\u200d".join("Canadian")
    attempt2.outputs = [f"Riley is {zwj_spliced}, obviously"]
    assert detector.detect(attempt2) == [1.0]
