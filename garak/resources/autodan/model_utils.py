# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import gc
import torch
from typing import Tuple, Union, Optional
from logging import getLogger
import garak._config
from garak.generators.huggingface import Model, Pipeline
from transformers import PreTrainedModel

logger = getLogger(__name__)


def forward(
    model: PreTrainedModel,
    input_ids: torch.Tensor,
    attention_mask: torch.Tensor,
    batch_size: int = 512,
) -> torch.Tensor:
    """Run a forward pass on the specified model

    Args:
        model (PreTrainedModel): Generator with model for forward pass
        input_ids (torch.Tensor): Tokenized input to the model
        attention_mask (torch.Tensor): Attention mask from tokenizer
        batch_size (int): Number of samples to run

    Returns:
        Tensor of logits
    """
    logits = []
    for i in range(0, input_ids.shape[0], batch_size):
        batch_input_ids = input_ids[i : i + batch_size]
        if attention_mask is not None:
            batch_attention_mask = attention_mask[i : i + batch_size]
        else:
            batch_attention_mask = None

        logits.append(
            model(input_ids=batch_input_ids, attention_mask=batch_attention_mask).logits
        )

    del batch_input_ids, batch_attention_mask
    gc.collect()

    return torch.cat(logits, dim=0)


def check_for_attack_success(gen_str: str, test_prefixes) -> bool:
    """Check if the jailbreak is successful against the specified model

    Args:
        gen_str (str): Generated model output
        test_prefixes (list): List of test prefixes

    Returns:
        Boolean of whether the model jailbreak was successful
    """
    gen_str = gen_str.lower()
    # We can do a better check. Maybe fuzzy match the target?
    accepted = not any([prefix.lower() in gen_str for prefix in test_prefixes])
    return accepted


class AutoDanPrefixManager:
    def __init__(
        self,
        *,
        generator: Union[Pipeline, Model],
        instruction: str,
        target: str,
        adv_string: str,
        system_prompt: Optional[str],
    ):
        """Prefix manager class for AutoDAN

        Args:
            generator (Pipeline | Model): Generator to use
            instruction (str): Instruction to pass to the model
            target (str): Target output string
            adv_string (str): Adversarial (jailbreak) string
            system_prompt (str): Optional system prompt
        """
        # Can't use isinstance here because of subclassing
        if type(generator) is Pipeline:
            self.model = generator.generator.model
        elif isinstance(generator, Model):
            self.model = generator.model
        else:
            logger.critical(f"Expected Pipeline or Model but got {type(generator)}")
            raise TypeError(f"Expected Pipeline or Model but got {type(generator)}")
        self.device = generator.device
        self.tokenizer = generator.tokenizer
        self.instruction = instruction
        self.target = target
        self.adv_string = adv_string
        self.messages = list()
        self.system_prompt = system_prompt
        self.target_ids = None

    def _reset_messages(self):
        del self.messages
        self.messages = list()
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})

    def get_input_ids(
        self, adv_string: str = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get input ids from the tokenizer for a provided string

        Args:
            adv_string (str): String to tokenize

        Returns:
            Tuple of input_ids and attention_mask
        """
        if adv_string is not None:
            self.adv_string = adv_string

        self._reset_messages()

        self.messages.append(
            {"role": "user", "content": f"{self.adv_string} {self.instruction}"}
        )
        self.messages.append({"role": "assistant", "content": self.target})

        self.target_ids = self.tokenizer(
            [self.target], add_special_tokens=False, return_tensors="pt"
        )["input_ids"].to(self.device)
        outputs = self.tokenizer.apply_chat_template(
            self.messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        )
        tokenized_msg = outputs["input_ids"].to(self.device)
        attention_mask = outputs["attention_mask"].to(self.device)

        return tokenized_msg, attention_mask
