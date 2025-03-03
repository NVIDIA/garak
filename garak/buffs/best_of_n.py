# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Buff that uses Best-of-N Jailbreaking to generate multiple attempts. """
import random
from collections.abc import Iterable

import garak.attempt
from garak.buffs.base import Buff


def apply_word_scrambling(text: str, prob: float) -> str:
    """
    Scrambles the middle characters of words longer than 3 characters in the input text.
    The probability of scrambling is determined by sigma.

    Example:
    Input: "The quick brown fox jumps"
    Output: "The qiuck bwron fox jpums"
    """
    words = text.split()
    scrambled_words = []
    for word in words:
        if len(word) > 3 and random.random() < prob:
            chars = list(word)
            middle_chars = chars[1:-1]
            random.shuffle(middle_chars)
            scrambled_word = chars[0] + "".join(middle_chars) + chars[-1]
            scrambled_words.append(scrambled_word)
        else:
            scrambled_words.append(word)
    return " ".join(scrambled_words)


def apply_random_capitalization(text: str, prob: float) -> str:
    """
    Randomly capitalizes letters in the input text.

    Input: "The quick brown fox jumps"
    Output: "The qUick bRoWn fOx jUmps"
    """
    new_text = []
    for c in text:
        if c.isalpha() and random.random() < prob:
            if "a" <= c <= "z":
                new_text.append(chr(ord(c) - 32))  # Convert to uppercase
            elif "A" <= c <= "Z":
                new_text.append(chr(ord(c) + 32))  # Convert to lowercase
        else:
            new_text.append(c)
    return "".join(new_text)


def apply_ascii_noising(text: str, prob: float) -> str:
    """
    Perturbs the ASCII characters of the input text.

    Example:
    Input: "The quick brown fox jumps"
    Output: "Tge quick brown fox junps"
    """
    new_text = []
    for c in text:
        if c.isprintable() and random.random() < prob:
            perturbation = random.choice([-1, 1])
            new_char_code = ord(c) + perturbation
            # Ensure new character is printable ASCII
            if 32 <= new_char_code <= 126:
                new_text.append(chr(new_char_code))
            else:
                new_text.append(c)
        else:
            new_text.append(c)
    return "".join(new_text)


class BestOfNBuff(Buff):
    """Best of N buff

    Uses the following options from ``_config.plugins.generators["best_of_n.BestOfNBuff"]``:
    * ``num_attempts`` - (optional) the number of attempts to generate; defaults to 2
    * ``word_scrambling_prob`` - (optional) the probability of scrambling words; defaults to 0.6
    * ``random_capitalization_prob`` - (optional) the probability of random capitalization; defaults to 0.6
    * ``ascii_noising_prob`` - (optional) the probability of ASCII noising; defaults to 0.06

    This buff applies random transformations to generate multiple jailbreak attempts by:
    * Scrambling the words in the prompt
    * Randomly capitalizing letters in the prompt
    * Perturbing the ASCII characters in the prompt
    """

    DEFAULT_PARAMS = Buff.DEFAULT_PARAMS | {
        "num_attempts": 2,
        "word_scrambling_prob": 0.6,
        "random_capitalization_prob": 0.6,
        "ascii_noising_prob": 0.06,
    }

    doc_uri = "https://arxiv.org/abs/2412.03556"

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        prompt = attempt.prompt
        attempt.notes["original_prompt"] = prompt
        for _ in range(self.num_attempts):
            new_prompt = apply_word_scrambling(prompt, self.word_scrambling_prob)
            new_prompt = apply_random_capitalization(new_prompt, self.random_capitalization_prob)
            new_prompt = apply_ascii_noising(new_prompt, self.ascii_noising_prob)
            attempt.prompt = new_prompt
            yield self._derive_new_attempt(attempt)
