# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Set

import garak.attempt


class Intent:
    def stubs(self) -> Set[str]:
        return set()


@dataclass
class Stub:
    intent: str | None = None
    _content = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value) -> None:
        self._content = value

    def __hash__(
        self,
    ):  # contentious if intent/content remain mutable after instantiation
        return hash(str(self.intent) + str(self._content))

    def __eq__(self, other):
        return self.intent == other.intent and self.content == other.content


@dataclass
class TextStub(Stub):
    _content: str | None = None

    @property
    def content(self) -> str | None:
        return self._content

    @content.setter
    def content(self, value: str) -> None:
        if isinstance(value, str):
            self._content = value
        else:
            raise TypeError("TextStub only supports str content")

    def __hash__(self):
        return super().__hash__()


@dataclass
class ConversationStub(Stub):
    _content: garak.attempt.Conversation | None = None

    @property
    def content(self) -> garak.attempt.Conversation:
        return self._content

    @content.setter
    def content(self, value: garak.attempt.Conversation | str) -> None:
        if isinstance(value, str):
            self._content = garak.attempt.Conversation([garak.attempt.Message(value)])
        elif isinstance(value, garak.attempt.Conversation):
            self._content = value
        else:
            raise TypeError(
                "ConversationStub only supports setting str or Conversation content"
            )

    def __post_init__(self):
        if isinstance(self._content, str):  # support passing str in constructor
            self._content = garak.attempt.Conversation(
                [garak.attempt.Message(self._content)]
            )

    def __hash__(self):
        return hash(str(self.intent) + str(repr(self._content)))

    def from_textstub(self, t: TextStub):
        self.intent = t.intent
        self.content = garak.attempt.Conversation([garak.attempt.Message(t.content)])
