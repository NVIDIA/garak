# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


""" Translator that translates a prompt. """


from typing import List
import re
import unicodedata
import string
import logging
from garak.resources.api import nltk
from nltk.corpus import words
from langdetect import detect, DetectorFactory, LangDetectException
import json

# Ensure the NLTK words corpus is downloaded
try:
    nltk.data.find("corpora/words")
except LookupError as e:
    nltk.download("words", quiet=True)


def remove_english_punctuation(text: str) -> str:
    punctuation_without_apostrophe = string.punctuation.replace("'", "")
    return " ".join(
        re.sub(":|,", "", char)
        for char in text
        if char not in punctuation_without_apostrophe
    )


def is_english(text):
    """
    Determines if the given text is predominantly English based on word matching.

    Args:
        text (str): The text to evaluate.

    Returns:
        bool: True if more than 50% of the words are English, False otherwise.
    """
    # Load English words from NLTK
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
        ": " in input_text
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
        if unicodedata.category(char) not in {"Cf", "Cn", "Zs"}:
            return False
    return True


def is_meaning_string(text: str) -> bool:
    """Check if the input text is a meaningless sequence or invalid for translation."""
    DetectorFactory.seed = 0

    # Detect Language: Skip if no valid language is detected
    try:
        lang = detect(text)
        logging.debug(f"Detected language: {lang} text {text}")
    except LangDetectException:
        logging.debug("Could not detect a valid language.")
        return False

    if lang == "en":
        return False

    # Length and pattern checks: Skip if it's too short or repetitive
    if len(text) < 3 or re.match(r"(.)\1{3,}", text):  # e.g., "aaaa" or "123123"
        logging.debug(f"Detected short or repetitive sequence. text {text}")
        return False

    return True


def convert_json_string(json_string):
    # Replace single quotes with double quotes
    json_string = re.sub(r"'", '"', json_string)

    # Replace True with true
    json_string = re.sub("True", "true", json_string)

    # Replace False with false
    json_string = re.sub("False", "false", json_string)

    return json_string


# To be `Configurable` the root object must met the standard type search criteria
# { translators:
#     "local": { # model_type
#       "language": "<from>-<to>"
#       "name": "model/name" # model_name
#       "hf_args": {} # or any other translator specific values for the model_type
#     }
# }
from garak.configurable import Configurable


class Translator(Configurable):
    """Base class for objects that execute translation"""

    def __init__(self, config_root: dict = {}) -> None:
        self._load_config(config_root=config_root)

        self.translator = None
        self.nmt_client = None
        self.source_lang, self.target_lang = self.language.split("-")

        self._validate_env_var()

        self._load_translator()

    def _load_translator(self):
        raise NotImplementedError

    def _translate(self, text: str) -> str:
        raise NotImplementedError

    def _get_response(self, input_text: str):
        if self.source_lang is None or self.target_lang is None:
            return input_text

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

    def translate_prompts(
        self,
        prompts: List[str],
        reverse_translate_judge: bool = False,
    ) -> List[str]:
        if (
            hasattr(self, "target_lang") is False
            or self.source_lang == "*"
            or self.target_lang == ""
        ):
            return prompts
        translated_prompts = []
        prompts_to_process = list(prompts)
        for prompt in prompts_to_process:
            if reverse_translate_judge:
                mean_word_judge = is_meaning_string(prompt)
                if mean_word_judge:
                    translate_prompt = self._get_response(prompt)
                    translated_prompts.append(translate_prompt)
                else:
                    translated_prompts.append(prompt)
            else:
                translate_prompt = self._get_response(prompt)
                translated_prompts.append(translate_prompt)
        logging.debug(f"translated_prompts: {translated_prompts}")
        return translated_prompts

    def translate_descr(self, attempt_descrs: List[str]) -> List[str]:
        translated_attempt_descrs = []
        for descr in attempt_descrs:
            descr = json.loads(convert_json_string(descr))
            if type(descr["prompt_stub"]) is list:
                translate_prompt_stub = self.translate_prompts(descr["prompt_stub"])
            else:
                translate_prompt_stub = self.translate_prompts([descr["prompt_stub"]])
            if type(descr["payload"]) is list:
                translate_payload = self.translate_prompts(descr["payload"])
            else:
                translate_payload = self.translate_prompts([descr["payload"]])
            translated_attempt_descrs.append(
                str(
                    {
                        "prompt_stub": translate_prompt_stub,
                        "distractor": descr["distractor"],
                        "payload": translate_payload,
                        "az_only": descr["az_only"],
                        "use refocusing statement": descr["use refocusing statement"],
                    }
                )
            )
        return translated_attempt_descrs
