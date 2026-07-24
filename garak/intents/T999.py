# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test intents"""

from typing import Set

from garak.intents.base import Intent, Stub, TextStub


class Test(Intent):
    def stubs(self) -> Set[Stub]:
        return set(
            [
                TextStub("test"),
            ]
        )
