# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Buff that applies Turkish locale case mapping to prompts."""

from collections.abc import Iterable

import garak.attempt
from garak.buffs.base import Buff

# Turkish is a "dotted/dotless i" locale: it keeps the dot as a distinguishing
# feature across case changes, so I/ı and İ/i are two separate letter pairs.
# Unicode's default (locale-independent) case mapping, which str.lower() and
# str.casefold() implement, maps both capitals onto dotted i.
TURKISH_LOWER = str.maketrans({"I": "ı", "İ": "i"})
TURKISH_UPPER = str.maketrans({"i": "İ", "ı": "I"})


def turkish_lower(text: str) -> str:
    """Lower-case text the way a tr locale does, not the way str.lower() does."""
    return text.translate(TURKISH_LOWER).lower()


def turkish_upper(text: str) -> str:
    """Upper-case text the way a tr locale does, not the way str.upper() does."""
    return text.translate(TURKISH_UPPER).upper()


class TurkishLowercase(Buff):
    """Turkish locale lowercasing buff

    Lower-cases prompts using Turkish casing rules, where capital I maps to
    dotless ı rather than to i. Filters that normalise with str.lower() before
    matching a keyword list therefore stop matching -- "IGNORE" becomes
    "ıgnore", which no longer contains "ignore" -- while the text stays
    readable to a model. Compare buffs.lowercase.Lowercase, which applies the
    default Unicode mapping and does match."""

    doc_uri = "https://www.unicode.org/Public/UCD/latest/ucd/SpecialCasing.txt"
    lang = "*"

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        last_message = attempt.prompt.last_message()
        delattr(attempt, "_prompt")  # hack to allow prompt set
        attempt.prompt = garak.attempt.Message(
            text=turkish_lower(last_message.text), lang=last_message.lang
        )
        yield attempt


class TurkishUppercase(Buff):
    """Turkish locale uppercasing buff

    Upper-cases prompts using Turkish casing rules, where i maps to dotted İ
    rather than to I. A filter that upper-cases before matching sees "İGNORE"
    instead of "IGNORE"; one that lower-cases İ back down gets "i̇gnore", where
    the dot survives as a combining mark (U+0307) and still fails an equality
    test against "ignore"."""

    doc_uri = "https://www.unicode.org/Public/UCD/latest/ucd/SpecialCasing.txt"
    lang = "*"

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        last_message = attempt.prompt.last_message()
        delattr(attempt, "_prompt")  # hack to allow prompt set
        attempt.prompt = garak.attempt.Message(
            text=turkish_upper(last_message.text), lang=last_message.lang
        )
        yield attempt
