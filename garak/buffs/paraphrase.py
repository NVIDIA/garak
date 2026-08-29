# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Buff that paraphrases a prompt."""

from collections.abc import Iterable

import garak.attempt
from garak import _config
from garak.buffs.base import Buff
from garak.resources.api.huggingface import HFCompatible


class PegasusT5(Buff, HFCompatible):
    """Paraphrasing buff using Pegasus model"""

    DEFAULT_PARAMS = Buff.DEFAULT_PARAMS | {
        "para_model_name": "garak-llm/pegasus_paraphrase",
        "hf_args": {
            "device": "cpu",
            "trust_remote_code": False,
        },  # torch_dtype doesn't have standard support in Pegasus
        "max_length": 60,
        "temperature": 1.5,
    }
    lang = "en"
    doc_uri = "https://huggingface.co/tuner007/pegasus_paraphrase"
    _unsafe_attributes = ["para_model", "tokenizer"]

    def __init__(self, config_root=_config) -> None:
        self.num_return_sequences = 6
        self.num_beams = self.num_return_sequences
        self.tokenizer = None
        self.para_model = None
        super().__init__(config_root=config_root)

    def _load_unsafe(self):
        from transformers import PegasusForConditionalGeneration, PegasusTokenizer
        import os

        # disable huggingface attempts to open PRs in public sources
        disable_env_key = "DISABLE_SAFETENSORS_CONVERSION"
        stored_env = os.getenv(disable_env_key, default=None)
        os.environ[disable_env_key] = "true"

        self.device = self._select_hf_device()
        self.para_model = PegasusForConditionalGeneration.from_pretrained(
            self.para_model_name
        ).to(self.device)
        self.tokenizer = PegasusTokenizer.from_pretrained(
            self.para_model_name, trust_remote_code=self.hf_args["trust_remote_code"]
        )

        if stored_env:
            os.environ[disable_env_key] = stored_env
        else:
            del os.environ[disable_env_key]

    def _get_response(self, input_text):
        if self.para_model is None:
            self._load_unsafe()

        batch = self.tokenizer(
            [input_text],
            truncation=True,
            padding="longest",
            max_length=self.max_length,
            return_tensors="pt",
        ).to(self.device)
        translated = self.para_model.generate(
            **batch,
            max_length=self.max_length,
            num_beams=self.num_beams,
            num_return_sequences=self.num_return_sequences,
            temperature=self.temperature,
        )
        tgt_text = self.tokenizer.batch_decode(translated, skip_special_tokens=True)
        return tgt_text

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        yield self._derive_new_attempt(
            attempt
        )  # why does this yield a copy of the original with no modification?
        last_message = attempt.prompt.last_message()
        paraphrases = self._get_response(last_message.text)
        for paraphrase in set(paraphrases):
            paraphrased_attempt = self._derive_new_attempt(attempt)
            # transform receives a copy of the attempt should it modify the prompt in place?
            delattr(paraphrased_attempt, "_prompt")  # hack to allow prompt set
            paraphrased_attempt._prompt = garak.attempt.Message(
                text=paraphrase, lang=last_message.lang
            )
            yield paraphrased_attempt


class Fast(Buff, HFCompatible):
    """CPU-friendly paraphrase buff based on Humarin's T5 paraphraser"""

    DEFAULT_PARAMS = Buff.DEFAULT_PARAMS | {
        "para_model_name": "garak-llm/chatgpt_paraphraser_on_T5_base",
        "hf_args": {
            "device": "cpu",
            "torch_dtype": "float32",
            "custom_generate": "transformers-community/group-beam-search",
            "trust_remote_code": True,
        },
    }
    lang = "en"
    doc_uri = "https://huggingface.co/humarin/chatgpt_paraphraser_on_T5_base"
    _unsafe_attributes = ["para_model", "tokenizer"]

    def __init__(self, config_root=_config) -> None:
        self.num_beams = 5
        self.num_beam_groups = 5
        self.num_return_sequences = 5
        self.repetition_penalty = 10.0
        self.diversity_penalty = 3.0
        self.no_repeat_ngram_size = 2
        # self.temperature = 0.7
        self.max_length = 128
        self.tokenizer = None
        self.para_model = None
        super().__init__(config_root=config_root)

    def _load_unsafe(self):
        from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
        import os

        # disable huggingface attempts to open PRs in public sources
        disable_env_key = "DISABLE_SAFETENSORS_CONVERSION"
        stored_env = os.getenv(disable_env_key, default=None)
        os.environ[disable_env_key] = "true"

        self.device = self._select_hf_device()
        model_kwargs = self._gather_hf_params(
            hf_constructor=AutoModelForSeq2SeqLM.from_pretrained
        )  # will defer to device_map if device map was `auto` may not match self.device
        generation_params = self._gather_generation_params()
        for param in generation_params.keys():
            if param in model_kwargs.keys():
                model_kwargs.pop(param)

        if self.hf_args.get("custom_generate", None):
            if not self.hf_args.get("trust_remote_code", False):
                raise ValueError(
                    "When using a 'custom_generate' option 'trust_remote_code' must be enabled."
                )

        self.para_model = AutoModelForSeq2SeqLM.from_pretrained(
            self.para_model_name, **model_kwargs
        ).to(self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(self.para_model_name)

        for k, v in generation_params.items():
            setattr(self.para_model.generation_config, k, v)

        if stored_env:
            os.environ[disable_env_key] = stored_env
        else:
            del os.environ[disable_env_key]

    def _get_response(self, input_text):
        if self.para_model is None:
            self._load_unsafe()

        input_ids = self.tokenizer(
            f"paraphrase: {input_text}",
            return_tensors="pt",
            padding="longest",
            max_length=self.max_length,
            truncation=True,
        ).input_ids

        try:
            outputs = self.para_model.generate(
                input_ids,
                # temperature=self.temperature,
                repetition_penalty=self.repetition_penalty,
                num_return_sequences=self.num_return_sequences,
                no_repeat_ngram_size=self.no_repeat_ngram_size,
                num_beams=self.num_beams,
                num_beam_groups=self.num_beam_groups,
                max_length=self.max_length,
                diversity_penalty=self.diversity_penalty,
                # requirements for custom generation in transformers >= 4.57.0
                trust_remote_code=self.hf_args["trust_remote_code"],
            )
        except OSError as e:
            from garak.exception import GarakException

            msg = f"{self.__module__}.{self.__class__.__name__} failed to generate a model response"
            raise GarakException(msg) from e

        res = self.tokenizer.batch_decode(outputs, skip_special_tokens=True)

        return res

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        yield self._derive_new_attempt(
            attempt
        )  # why does this yield a copy of the original with no modification?
        last_message = attempt.prompt.last_message()
        paraphrases = self._get_response(last_message.text)
        for paraphrase in set(paraphrases):
            paraphrased_attempt = self._derive_new_attempt(attempt)
            # transform receives a copy of the attempt should it modify the prompt in place?
            delattr(paraphrased_attempt, "_prompt")  # hack to allow prompt set
            paraphrased_attempt._prompt = garak.attempt.Message(
                text=paraphrase, lang=last_message.lang
            )
            yield paraphrased_attempt
