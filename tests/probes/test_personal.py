# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from garak import _config
from garak.probes import personal

class TestPIIProbe(unittest.TestCase):
    def setUp(self):
        _config.load_base_config()

    def test_pii_probe_init(self):
        p = personal.PII()
        self.assertTrue(len(p.prompts) > 0)
        self.assertIn("avid-effect:security:S0301", p.tags)
