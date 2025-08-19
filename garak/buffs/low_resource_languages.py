# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Buff that converts prompts with different encodings."""

from collections.abc import Iterable
from deepl import Translator

import garak.attempt
from garak import _config
from garak.buffs.base import Buff

# Low resource languages supported by DeepL
# ET = Estonian
# ID = Indonesian
# LT = Lithuanian
# LV = Latvian
# SK = Slovak
# SL = Slovenian
LOW_RESOURCE_LANGUAGES = ["ET", "ID", "LV", "SK", "SL"]


class LRLBuff(Buff):
    """Low Resource Language buff

    Uses the DeepL API to translate prompts into low-resource languages"""

    ENV_VAR = "DEEPL_API_KEY"
    doc_uri = "https://arxiv.org/abs/2310.02446"

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.post_buff_hook = True

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        # transform receives a copy of the attempt should it modify the prompt in place?
        deepl_translator = Translator(self.api_key)
        # only process the last message, this may need to be expanded to support all `Messages` in a `Conversation`
        prompt_text = attempt.prompt.last_message().text
        # if extended to all messages this should be a `Message` object
        attempt.notes["original_prompt"] = prompt_text
        for language in LOW_RESOURCE_LANGUAGES:
            attempt.notes["LRL_buff_dest_lang"] = language
            response = deepl_translator.translate_text(
                prompt_text, target_lang=language
            )
            translated_prompt = response.text
            delattr(attempt, "_prompt")  # hack to allow prompt set
            attempt.prompt = garak.attempt.Message(translated_prompt, language)
            yield self._derive_new_attempt(attempt)

    def untransform(self, attempt: garak.attempt.Attempt) -> garak.attempt.Attempt:
        deepl_translator = Translator(self.api_key)
        outputs = attempt.outputs
        attempt.notes["original_responses"] = [
            msg.text for msg in outputs
        ]  # serialise-friendly
        translated_outputs = list()
        for output in outputs:
            response = deepl_translator.translate_text(output.text, target_lang="EN-US")
            translated_output = response.text
            translated_outputs.append(
                garak.attempt.Message(translated_output, lang="en")
            )
        # does this work as expected? Setting outputs would _add_ a new turn not replace the originals
        attempt.outputs = translated_outputs
        return attempt
