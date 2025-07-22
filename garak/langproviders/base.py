# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


"""Translator that translates a prompt."""


from typing import List, Callable
import re
import unicodedata
import string
import logging
from garak.resources.api import nltk
from langdetect import detect, DetectorFactory, LangDetectException

_intialized_words = False


def _initialize_words():
    global _intialized_words
    if not _intialized_words:
        # Ensure the NLTK words corpus is downloaded
        try:
            nltk.data.find("corpora/words")
        except LookupError as e:
            nltk.download("words", quiet=True)
        _intialized_words = True


def remove_english_punctuation(text: str) -> str:
    punctuation_without_apostrophe = string.punctuation.replace("'", "")
    return " ".join(
        re.sub(":|,", "", char)
        for char in text
        if char not in punctuation_without_apostrophe
    )


def is_english(text):
    """Determines if the given text is predominantly English based on word matching.

    Args:
        text (str): The text to evaluate.

    Returns:
        bool: True if more than 50% of the words are English, False otherwise.
    """
    # Load English words from NLTK
    _initialize_words()
    from nltk.corpus import words

    special_terms = {"ascii85", "encoded", "decoded", "acsii", "plaintext"}
    english_words = set(words.words()).union(special_terms)

    text = text.lower()
    word_list = text.split()
    if len(word_list) == 0:
        return False

    if len(word_list) >= 1:
        word_list = remove_english_punctuation(word_list)
    else:
        word_list = word_list[0]

    if word_list:
        word_list = word_list.split()
        cleaned_words = " ".join(char for char in word_list if char.isalpha())
        # Filter out empty strings
        cleaned_words = cleaned_words.split()
        cleaned_words = [word for word in cleaned_words if word]

        if not cleaned_words:
            return False

        english_word_count = sum(1 for word in cleaned_words if word in english_words)
        return (english_word_count / len(cleaned_words)) > 0.5
    return False


def split_input_text(input_text: str) -> list:
    """Split input text based on the presence of ': '."""
    if (
        input_text is not None
        and ": " in input_text
        and "http://" not in input_text
        and "https://" not in input_text
    ):
        split_text = input_text.splitlines()
        split_text = [line.split(":") for line in split_text]
        split_text = [item for sublist in split_text for item in sublist]
    else:
        split_text = input_text.splitlines()
    return split_text


def contains_invisible_unicode(text: str) -> bool:
    """Determine whether the text contains invisible Unicode characters."""
    if not text:
        return False
    for char in text:
        if unicodedata.category(char) not in {"Cc", "Cf", "Cn", "Zl", "Zp", "Zs"}:
            return False
    return True


def is_meaning_string(text: str) -> bool:
    """Check if the input text is a meaningless sequence or invalid for translation."""
    DetectorFactory.seed = 0

    # Detect Language: Skip if no valid language is detected
    try:
        lang = detect(text)
    except LangDetectException:
        logging.debug("langdetect failed to detect a valid language.")
        return False

    if lang == "en":
        return False

    # Length and pattern checks: Skip if it's too short or repetitive
    if len(text) < 3 or re.match(r"(.)\1{3,}", text):  # e.g., "aaaa" or "123123"
        return False

    return True


# To be `Configurable` the root object must meet the standard type search criteria
# { langproviders:
#     "local": { # model_type
#       "language": "<from>-<to>"
#       "name": "model/name" # model_name
#       "hf_args": {} # or any other translator specific values for the model_type
#     }
# }
from garak.configurable import Configurable


class LangProvider(Configurable):
    """Base class for objects that provision language"""

    def __init__(self, config_root: dict = {}) -> None:

        self._load_config(config_root=config_root)

        self.source_lang, self.target_lang = self.language.split(",")

        self._validate_env_var()

        self._load_langprovider()

    def _load_langprovider(self):
        raise NotImplementedError

    def _translate(self, text: str) -> str:
        raise NotImplementedError

    def _get_response(self, input_text: str):
        translated_lines = []

        split_text = split_input_text(input_text)

        for line in split_text:
            if self._should_skip_line(line):
                if contains_invisible_unicode(line):
                    continue
                translated_lines.append(line.strip())
                continue
            if contains_invisible_unicode(line):
                continue
            if len(line) <= 200:
                translated_lines += self._short_sentence_translate(line)
            else:
                translated_lines += self._long_sentence_translate(line)

        return "\n".join(translated_lines)

    def _short_sentence_translate(self, line: str) -> str:
        translated_lines = []
        needs_translation = True
        if self.source_lang == "en" or line == "$":
            # why is "$" a special line?
            mean_word_judge = is_english(line)
            if not mean_word_judge or line == "$":
                translated_lines.append(line.strip())
                needs_translation = False
            else:
                needs_translation = True
        if needs_translation:
            cleaned_line = self._clean_line(line)
            if cleaned_line:
                translated_line = self._translate(cleaned_line)
                translated_lines.append(translated_line)

        return translated_lines

    def _long_sentence_translate(self, line: str) -> str:
        translated_lines = []
        sentences = re.split(r"(\. |\?)", line.strip())
        for sentence in sentences:
            cleaned_sentence = self._clean_line(sentence)
            if self._should_skip_line(cleaned_sentence):
                translated_lines.append(cleaned_sentence)
                continue
            translated_line = self._translate(cleaned_sentence)
            translated_lines.append(translated_line)

        return translated_lines

    def _should_skip_line(self, line: str) -> bool:
        return (
            line.isspace()
            or line.strip().replace("-", "") == ""
            or len(line) == 0
            or line.replace(".", "") == ""
            or line in {".", "?", ". "}
        )

    def _clean_line(self, line: str) -> str:
        return remove_english_punctuation(line.strip().lower().split())

    def get_text(
        self,
        prompts: List[str],
        reverse_translate_judge: bool = False,
        notify_callback: Callable | None = None,
    ) -> List[str]:
        translated_prompts = []
        prompts_to_process = list(prompts)
        for prompt in prompts_to_process:
            translate_prompt = prompt
            if prompt is not None:
                if reverse_translate_judge:
                    mean_word_judge = is_meaning_string(prompt)
                    if mean_word_judge:
                        translate_prompt = self._get_response(prompt)
                else:
                    translate_prompt = self._get_response(prompt)
            translated_prompts.append(translate_prompt)
            if notify_callback:
                notify_callback()
        return translated_prompts
