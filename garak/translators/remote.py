# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


""" Translator that translates a prompt. """


import logging

from garak.exception import BadGeneratorException
from garak.translators.base import Translator


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
    bcp47_support = [
        "zh", "ru", "de", "es", "fr",
        "da", "el", "fi", "hu", "it",
        "lt", "lv", "nl", "no", "pl",
        "pt", "ro", "sk", "sv", "ja",
        "hi", "ko", "et", "sl", "bg",
        "uk", "hr", "ar", "vi", "tr",
        "id", "cs", "en"
    ]
    # fmt: on

    # avoid attempt to pickle the client attribute
    def __getstate__(self) -> object:
        self._clear_translator()
        return dict(self.__dict__)

    # restore the client attribute
    def __setstate__(self, d) -> object:
        self.__dict__.update(d)
        self._load_translator()

    def _clear_translator(self):
        self.nmt_client = None

    def _load_translator(self):
        if not (
            self.source_lang in self.bcp47_support
            and self.target_lang in self.bcp47_support
        ):
            raise BadGeneratorException(
                f"Language pair {self.source_lang}-{self.target_lang} is not supported for this translator service."
            )

        import riva.client

        if self.nmt_client is None:
            auth = riva.client.Auth(
                None,
                self.use_ssl,
                self.uri,
                [
                    ("function-id", self.function_id),
                    ("authorization", "Bearer " + self.api_key),
                ],
            )
            self.nmt_client = riva.client.NeuralMachineTranslationClient(auth)

    def _translate(self, text: str) -> str:
        try:
            response = self.nmt_client.translate(
                [text], "", self.source_lang, self.target_lang
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
    bcp47_support = [
        "ar", "bg", "cs", "da", "de",  
        "en", "el", "es", "et", "fi",
        "fr", "hu", "id", "it", "ja",
        "ko", "lt", "lv", "nb", "nl",
        "pl", "pt", "ro", "ru", "sk",
        "sl", "sv", "tr", "uk", "zh",
        "en"
    ]
    # fmt: on

    def _load_translator(self):
        from deepl import Translator

        if not (
            self.source_lang in self.bcp47_support
            and self.target_lang in self.bcp47_support
        ):
            raise BadGeneratorException(
                f"Language pair {self.source_lang}-{self.target_lang} is not supported for this translator service."
            )

        if self.translator is None:
            self.translator = Translator(self.api_key)

    def _translate(self, text: str) -> str:
        try:
            target_lang = "EN-US" if self.target_lang == "en" else self.target_lang
            return self.translator.translate_text(
                text, source_lang=self.source_lang, target_lang=target_lang
            ).text
        except Exception as e:
            logging.error(f"Translation error: {str(e)}")
            return text


DEFAULT_CLASS = "RivaTranslator"
