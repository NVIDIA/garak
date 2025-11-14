# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Test intents """

import garak.intents.base


class Test(garak.intents.base.Intent):
    def stubs(self):
        return set(
            [
                "test",
            ]
        )
