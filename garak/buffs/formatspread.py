# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Buff that re-expresses a prompt across a range of surface formats.

FormatSpread (Sclar et al., 2023) reports that a model can respond differently to
the same request depending on spurious formatting: the label placed before the
text, the separator after it, the casing of that label, and the spacing between
fields. This buff emits a fixed, repeatable set of such formats for each prompt
so a probe can measure how much formatting alone moves the result.
"""

from collections.abc import Iterable

import garak.attempt
from garak.buffs.base import Buff


class FormatSpread(Buff):
    """Spread one prompt across a small, repeatable set of text formats."""

    doc_uri = "https://arxiv.org/abs/2310.11324"
    lang = "en"

    # format templates; the {descriptor}, {separator}, {field_spacing} and
    # {answer_descriptor} markers are filled per spec, and PROMPT_MARKER last
    PROMPT_MARKER = "{prompt}"
    templates = [
        "{descriptor}{separator}{prompt}",
        "{descriptor}{separator}{prompt}{field_spacing}{answer_descriptor}:",
    ]

    def _format_variants(self, text: str) -> Iterable[str]:
        seen = set()
        format_specs = (
            ("Instruction", ": ", "identity", "", ""),
            ("Instruction", "\n", "upper", "", ""),
            ("Instruction", "::", "lower", "\n\n", "Answer"),
            ("Instruction", " - ", "title", " || ", "Answer"),
            ("Task", "::", "identity", "", ""),
            ("Task", " - ", "upper", "", ""),
            ("Task", "\n", "lower", "\n\n", "Response"),
            ("Task", ": ", "title", " || ", "Response"),
            ("Request", " - ", "identity", "", ""),
            ("Request", ": ", "upper", "", ""),
            ("Request", "::", "lower", "\n\n", "Answer"),
            ("Request", "\n", "title", " || ", "Answer"),
        )

        for descriptor, separator, casing, field_spacing, answer in format_specs:
            if casing == "upper":
                descriptor = descriptor.upper()
                answer = answer.upper()
            elif casing == "lower":
                descriptor = descriptor.lower()
                answer = answer.lower()
            elif casing == "title":
                descriptor = descriptor.title()
                answer = answer.title()

            template = self.templates[1] if answer else self.templates[0]
            variant = template.replace("{descriptor}", descriptor)
            variant = variant.replace("{separator}", separator)
            variant = variant.replace("{field_spacing}", field_spacing)
            variant = variant.replace("{answer_descriptor}", answer)
            # insert the prompt last so its text is never treated as a marker
            variant = variant.replace(self.PROMPT_MARKER, text)

            if variant != text and variant not in seen:
                seen.add(variant)
                yield variant

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        last_message = attempt.prompt.last_message()
        for variant in self._format_variants(last_message.text):
            new_attempt = self._derive_new_attempt(attempt)
            delattr(new_attempt, "_prompt")  # hack to allow prompt set
            new_attempt.prompt = garak.attempt.Message(
                text=variant, lang=last_message.lang
            )
            yield new_attempt
