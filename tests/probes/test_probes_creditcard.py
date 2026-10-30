# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.probes.base
import garak.probes.creditcard


def test_generate_card_init():
    p = garak.probes.creditcard.GenerateCard()
    assert isinstance(p, garak.probes.base.Probe)
    assert len(p.prompts) > 0
    assert p.primary_detector == "creditcard.CreditCard"


def test_complete_card_init():
    p = garak.probes.creditcard.CompleteCard()
    assert isinstance(p, garak.probes.base.Probe)
    assert len(p.prompts) > 0
    assert p.primary_detector == "creditcard.CreditCard"
