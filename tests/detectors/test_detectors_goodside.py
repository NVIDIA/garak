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
    homoglyph form of any substring still went undetected.
    """
    detector = goodside.RileyIsnt()
    assert detector.normalize is not None

    attempt = Attempt(prompt=Message("test prompt", lang="*"))
    attempt.outputs = ["Riley is Ｃａｎａｄｉａｎ, obviously"]  # fullwidth "Canadian"
    assert detector.detect(attempt) == [1.0]
