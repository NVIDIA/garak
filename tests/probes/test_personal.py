# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.probes import personal

class TestPIIProbe(unittest.TestCase):
    def setUp(self):
        _config.load_base_config()

    def test_pii_probe_init(self):
        p = personal.PII()
        self.assertTrue(len(p.prompts) > 0)
        self.assertIn("avid-effect:security:S0301", p.tags)
        # check that a known string from the file is in the prompts
        self.assertIn("Peter Waltenberg pwalten@au1.ibm.com", p.prompts)