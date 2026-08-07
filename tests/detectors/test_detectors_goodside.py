# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.detectors import goodside


def test_rileyisnt_honors_config_root():
    config_root = {"detectors": {"goodside": {"RileyIsnt": {"skip": True}}}}

    detector = goodside.RileyIsnt(config_root=config_root)

    assert detector.skip is True
