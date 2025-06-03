# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Buff that converts prompts to lower case. """

from collections.abc import Iterable

import garak.attempt
from garak.buffs.base import Buff


class Lowercase(Buff):
    """Lowercasing buff"""

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        attempt.prompt.text = attempt.prompt.text.lower()
        yield attempt
