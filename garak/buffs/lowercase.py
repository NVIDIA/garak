# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Buff that converts prompts to lower case."""

from collections.abc import Iterable
import copy

import garak.attempt
from garak.buffs.base import Buff


class Lowercase(Buff):
    """Lowercasing buff"""

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        if attempt.prompt is None or not attempt.prompt.turns:
            yield attempt
            return
        new_turns = []
        for turn in attempt.prompt.turns:
            new_text = (
                turn.content.text.lower() if turn.content.text is not None else None
            )
            new_msg = garak.attempt.Message(
                text=new_text,
                lang=turn.content.lang,
                data_path=turn.content.data_path,
                data_type=turn.content.data_type,
            )
            new_turns.append(garak.attempt.Turn(role=turn.role, content=new_msg))
        new_conv = garak.attempt.Conversation(
            turns=new_turns,
            notes=copy.deepcopy(attempt.prompt.notes) if attempt.prompt.notes else {},
        )
        delattr(attempt, "_prompt")  # hack to allow prompt set
        attempt.prompt = new_conv
        yield attempt
