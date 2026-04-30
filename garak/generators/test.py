"""Test generators

These give simple system responses, intended for testing.
"""

from typing import List

import lorem

from garak.attempt import Message, Conversation
from garak.generators.base import Generator


class Blank(Generator):
    """This generator always returns the empty string."""

    supports_multiple_generations = True
    generator_family_name = "Test"
    name = "Blank"

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        return [Message("")] * generations_this_call


class Repeat(Generator):
    """This generator returns the last message from input that was posed to it."""

    supports_multiple_generations = True
    generator_family_name = "Test"
    name = "Repeat"

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        return [prompt.last_message()] * generations_this_call


class Single(Generator):
    """This generator returns the a fixed string and does not support multiple generations."""

    supports_multiple_generations = False
    generator_family_name = "Test"
    name = "Single"
    test_generation_string = "ELIM"

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        if generations_this_call == 1:
            return [Message(self.test_generation_string)]
        else:
            raise ValueError(
                "Test generator refuses to generate > 1 at a time. Check generation logic"
            )


class Nones(Generator):
    """This generator always returns a None for every generation."""

    supports_multiple_generations = True
    generator_family_name = "Test"
    name = "Nones"

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        return [None] * generations_this_call


class Lipsum(Generator):
    """Lorem Ipsum generator, so we can get non-zero outputs that vary

    Configurable parameters:
        unit: str - content unit to generate per output.
            Must be one of "sentence", "paragraph", or "text".
        count: int - How many of the specified unit to join per output.
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "unit": "sentence",
        "count": 1,
    }

    supports_multiple_generations = False
    generator_family_name = "Test"
    name = "Lorem Ipsum"

    _unit_separators = {
        "sentence": " ",
        "paragraph": "\n",
        "text": "\n",
    }

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        if self.unit not in self._unit_separators:
            raise ValueError(
                f"Invalid unit '{self.unit}', must be one of {set(self._unit_separators)}"
            )
        generate = getattr(lorem, self.unit)
        sep = self._unit_separators[self.unit]
        return [
            Message(sep.join(generate() for _ in range(self.count)))
            for i in range(generations_this_call)
        ]


class ReasoningLipsum(Lipsum):
    """Lorem Ipsum generator with a simulated reasoning trace, for testing
    probe/detector behavior with long structured outputs.

    Generates output in the format:
        {skip_seq_start}{reasoning text}{skip_seq_end}{output text}

    Configurable parameters:
        skip_seq_start: str - Opening delimiter for the reasoning trace.
        skip_seq_end: str - Closing delimiter for the reasoning trace.
        reasoning_length: int - Target character count for the reasoning trace.
        output_length: int - Target character count for the output text.
        variance: float - Fraction (0.0–1.0) by which reasoning_length and
            output_length may deviate from configured values. 0.1 means ±10%.
        respect_max_tokens: bool - Cap the output text (not the
            reasoning trace) to approximately max_tokens * 1.4 characters.
    """

    DEFAULT_PARAMS = Lipsum.DEFAULT_PARAMS | {
        "skip_seq_start": "<think>",
        "skip_seq_end": "</think>",
        "reasoning_length": 2000,
        "output_length": 500,
        "variance": 0.1,
        "respect_max_tokens": False,
        "unit": "sentence",
    }

    supports_multiple_generations = False
    generator_family_name = "Test"
    name = "Reasoning Lipsum"

    def _generate_lorem(self, min_length: int, variance: float = 0.0) -> str:
        """Generate lorem text of approximately target_length characters.

        Builds up text sentence-by-sentence until the target is reached.

        Args:
            target_length: Target number of characters to generate.
            variance: Fraction (0.0–1.0) by which the actual length may
                randomly deviate from target_length. E.g. 0.1 means ±10%.
        """
        if variance > 0:
            deviation = self._rng.uniform(-variance, variance) * min_length
            min_length = max(1, int(min_length + deviation))

        if self.unit not in self._unit_separators:
            raise ValueError(
                f"Invalid unit '{self.unit}', must be one of {set(self._unit_separators)}"
            )

        gen_func = getattr(lorem, self.unit)

        lorem_text = gen_func()
        while len(lorem_text) < min_length:
            lorem_text += self._unit_separators[self.unit]
            lorem_text += gen_func()
        return lorem_text

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        output_length = self.output_length
        if self.respect_max_tokens and self.max_tokens is not None:
            token_char_budget = int(self.max_tokens * 1.4)
            output_length = min(output_length, token_char_budget)

        results = []
        for _ in range(generations_this_call):
            reasoning = self._generate_lorem(self.reasoning_length, self.variance)
            output = self._generate_lorem(output_length, self.variance)
            text = f"{self.skip_seq_start}{reasoning}{self.skip_seq_end}{output}"
            results.append(Message(text))
        return results


class BlankVision(Generator):
    """This text+image input generator always returns the empty string."""

    supports_multiple_generations = True
    generator_family_name = "Test"
    name = "BlankVision"
    modality = {"in": {"text", "image"}, "out": {"text"}}

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Message | None]:
        return [Message("")] * generations_this_call


DEFAULT_CLASS = "Lipsum"
