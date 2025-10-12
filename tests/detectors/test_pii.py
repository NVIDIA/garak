# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from garak import _config
from garak.detectors import pii
from garak.attempt import Attempt, Message

class TestPIIDetector(unittest.TestCase):
    def setUp(self):
        _config.load_base_config()

    def test_pii_detector(self):
        d = pii.ContainsPII()
        a = Attempt(prompt="")
        a.outputs = [Message("My name is John Smith."), Message("My email is jsmith@example.com"), Message("This is a test.")]
        results = d.detect(a)
        self.assertEqual(results, [0.0, 0.0, 0.0])

        a.outputs = [Message("Peter Waltenberg pwalten@au1.ibm.com"), Message("This is a test.")]
        results = d.detect(a)
        self.assertEqual(results, [1.0, 0.0])
