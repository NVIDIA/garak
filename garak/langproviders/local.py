# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


"""Local language providers & translators."""


from typing import List, Callable

from garak.exception import BadGeneratorException
from garak.langproviders.base import LangProvider
from garak.resources.api.huggingface import HFCompatible


class Passthru(LangProvider):
    """Stand-in language provision for pass through / noop"""

    def _load_langprovider(self):
        pass

    def _translate(self, text: str) -> str:
        return text

    def get_text(
        self,
        prompts: List[str],
        reverse_translate_judge: bool = False,
        notify_callback: Callable | None = None,
    ) -> List[str]:
        return prompts


class LocalHFTranslator(LangProvider, HFCompatible):
    """Local translation using Huggingface m2m100 or Helsinki-NLP/opus-mt-* models

    Reference:
      - https://huggingface.co/facebook/m2m100_1.2B
      - https://huggingface.co/facebook/m2m100_418M
      - https://huggingface.co/docs/transformers/model_doc/marian
    """

    DEFAULT_PARAMS = {
        "model_name": "Helsinki-NLP/opus-mt-{}",  # This is inconsistent with generators and may change to `name`.
        "hf_args": {
            "device": "cpu",
        },
    }

    def __init__(self, config_root: dict = {}) -> None:
        self._load_config(config_root=config_root)

        import torch.multiprocessing as mp

        # set_start_method for consistency, translation does not utilize multiprocessing
        mp.set_start_method("spawn", force=True)

        self.device = self._select_hf_device()
        super().__init__(config_root=config_root)

    def _load_langprovider(self):
        if "m2m100" in self.model_name:
            from transformers import M2M100ForConditionalGeneration, M2M100Tokenizer

            # fmt: off
            # Reference: https://huggingface.co/facebook/m2m100_418M#languages-covered
            lang_support = {
                "af", "am", "ar", "ast", "az",
                "ba", "be", "bg", "bn", "br",
                "bs", "ca", "ceb", "cs", "cy",
                "da", "de", "el", "en", "es",
                "et", "fa", "ff", "fi", "fr",
                "fy", "ga", "gd", "gl", "gu",
                "ha", "he", "hi", "hr", "ht",
                "hu", "hy", "id", "ig", "ilo",
                "is", "it", "ja", "jv", "ka",
                "kk", "km", "kn", "ko", "lb",
                "lg", "ln", "lo", "lt", "lv",
                "mg", "mk", "ml", "mn", "mr",
                "ms", "my", "ne", "nl", "no",
                "ns", "oc", "or", "pa", "pl",
                "ps", "pt", "ro", "ru", "sd",
                "si", "sk", "sl", "so", "sq",
                "sr", "ss", "su", "sv", "sw",
                "ta", "th", "tl", "tn", "tr",
                "uk", "ur", "uz", "vi", "wo",
                "xh", "yi", "yo", "zh", "zu",
            }
            # fmt: on
            if not (
                self.source_lang in lang_support and self.target_lang in lang_support
            ):
                raise BadGeneratorException(
                    f"Language pair {self.language} is not supported for this translation service."
                )

            self.model = M2M100ForConditionalGeneration.from_pretrained(
                self.model_name
            ).to(self.device)
            self.tokenizer = M2M100Tokenizer.from_pretrained(self.model_name)
        else:
            from transformers import MarianMTModel, MarianTokenizer

            # if model is not m2m100 expect the model name to be "Helsinki-NLP/opus-mt-{}" where the format string
            # is replace with the language path defined in the configuration as self.source_lang-self.target_lang
            # validation of all supported pairs is deferred in favor of allowing the download to raise exception
            # when no published model exists with the pair requested in the name.
            model_suffix = f"{self.source_lang}-{self.target_lang}"
            model_name = self.model_name.format(model_suffix)
            self.model = MarianMTModel.from_pretrained(model_name).to(self.device)
            self.tokenizer = MarianTokenizer.from_pretrained(model_name)

    def _translate(self, text: str) -> str:
        if "m2m100" in self.model_name:
            self.tokenizer.src_lang = self.source_lang

            encoded_text = self.tokenizer(text, return_tensors="pt").to(self.device)

            translated = self.model.generate(
                **encoded_text,
                forced_bos_token_id=self.tokenizer.get_lang_id(self.target_lang),
            )

            translated_text = self.tokenizer.batch_decode(
                translated, skip_special_tokens=True
            )[0]

            return translated_text
        else:
            # this assumes MarianMTModel type
            source_text = self.tokenizer([text], return_tensors="pt").to(self.device)

            translated = self.model.generate(**source_text)

            translated_text = self.tokenizer.batch_decode(
                translated, skip_special_tokens=True
            )[0]

            return translated_text


DEFAULT_CLASS = "LocalHFTranslator"
