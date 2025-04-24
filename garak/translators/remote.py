# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


"""Translator that translates a prompt."""


import logging

from garak.exception import BadGeneratorException
from garak.translators.base import Translator

VALIDATION_STRING = "A"  # just send a single ASCII character for a sanity check


class RivaTranslator(Translator):
    """Remote translation using NVIDIA Riva translation API

    https://developer.nvidia.com/riva
    """

    ENV_VAR = "RIVA_API_KEY"
    DEFAULT_PARAMS = {
        "uri": "grpc.nvcf.nvidia.com:443",
        "function_id": "647147c1-9c23-496c-8304-2e29e7574510",
        "use_ssl": True,
    }

    # fmt: off
    # Reference: https://docs.nvidia.com/nim/riva/nmt/latest/support-matrix.html#models
    lang_support = [
        "zh", "ru", "de", "es", "fr",
        "da", "el", "fi", "hu", "it",
        "lt", "lv", "nl", "no", "pl",
        "pt", "ro", "sk", "sv", "ja",
        "hi", "ko", "et", "sl", "bg",
        "uk", "hr", "ar", "vi", "tr",
        "id", "cs", "en"
    ]
    # fmt: on
    # Applied when a service only supports regions specific codes
    lang_overrides = {
        "es": "es-US",
        "zh": "zh-TW",
        "pr": "pt-PT",
    }

    # avoid attempt to pickle the client attribute
    def __getstate__(self) -> object:
        self._clear_translator()
        return dict(self.__dict__)

    # restore the client attribute
    def __setstate__(self, d) -> object:
        self.__dict__.update(d)
        self._load_translator()

    def _clear_translator(self):
        self.client = None

    def _load_translator(self):
        if not (
            self.source_lang in self.lang_support
            and self.target_lang in self.lang_support
        ):
            raise BadGeneratorException(
                f"Language pair {self.language} is not supported for {self.__class__.__name__} services at {self.uri}."
            )
        self._source_lang = self.lang_overrides.get(self.source_lang, self.source_lang)
        self._target_lang = self.lang_overrides.get(self.target_lang, self.target_lang)

        import riva.client

        auth = riva.client.Auth(
            None,
            self.use_ssl,
            self.uri,
            [
                ("function-id", self.function_id),
                ("authorization", "Bearer " + self.api_key),
            ],
        )
        self.client = riva.client.NeuralMachineTranslationClient(auth)
        if not hasattr(self, "_tested"):
            self.client.translate(
                [VALIDATION_STRING], "", self._source_lang, self._target_lang
            )  # exception handling is intentionally not implemented to raise on invalid config for remote services.
            self._tested = True

    # TODO: consider adding a backoff here and determining if a connection needs to be re-established
    def _translate(self, text: str) -> str:
        try:
            if self.client is None:
                self._load_translator()
            response = self.client.translate(
                [text], "", self._source_lang, self._target_lang
            )
            return response.translations[0].text
        except Exception as e:
            logging.error(f"Translation error: {str(e)}")
            return text


class DeeplTranslator(Translator):
    """Remote translation using DeepL translation API

    https://www.deepl.com/en/translator
    """

    ENV_VAR = "DEEPL_API_KEY"
    DEFAULT_PARAMS = {}

    # fmt: off
    # Reference: https://developers.deepl.com/docs/resources/supported-languages
    lang_support = [
        "ar", "bg", "cs", "da", "de",  
        "en", "el", "es", "et", "fi",
        "fr", "hu", "id", "it", "ja",
        "ko", "lt", "lv", "nb", "nl",
        "pl", "pt", "ro", "ru", "sk",
        "sl", "sv", "tr", "uk", "zh",
        "en"
    ]
    # fmt: on
    # Applied when a service only supports regions specific codes
    lang_overrides = {
        "en": "en-US",
    }

    def _load_translator(self):
        from deepl import Translator

        if not (
            self.source_lang in self.lang_support
            and self.target_lang in self.lang_support
        ):
            raise BadGeneratorException(
                f"Language pair {self.language} is not supported for {self.__class__.__name__} services."
            )
        self._source_lang = self.source_lang
        self._target_lang = self.lang_overrides.get(self.target_lang, self.target_lang)

        self.client = Translator(self.api_key)
        if not hasattr(self, "_tested"):
            self.client.translate_text(
                VALIDATION_STRING,
                source_lang=self._source_lang,
                target_lang=self._target_lang,
            )  # exception handling is intentionally not implemented to raise on invalid config for remote services.
            self._tested = True

    def _translate(self, text: str) -> str:
        try:
            return self.client.translate_text(
                text, source_lang=self._source_lang, target_lang=self._target_lang
            ).text
        except Exception as e:
            logging.error(f"Translation error: {str(e)}")
            return text


DEFAULT_CLASS = "RivaTranslator"
