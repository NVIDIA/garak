# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import gc
import torch
import fastchat.model as fsmodel
from logging import getLogger
from typing import Tuple

logger = getLogger(__name__)


def forward(
    generator, input_ids: torch, attention_mask, batch_size=512
) -> torch.Tensor:
    """Run a forward pass on the specified model

    Args:
        generator (garak.generators.huggingface.Model): Generator with model for forward pass
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
            generator.model(
                input_ids=batch_input_ids, attention_mask=batch_attention_mask
            ).logits
        )

        # Do we need to do garbage collection here?
        gc.collect()

    # Does this do anything since we return from the scope after this call?
    del batch_input_ids, batch_attention_mask

    return torch.cat(logits, dim=0)


def check_for_attack_success(gen_str: str, test_prefixes) -> bool:
    """Check if the jailbreak is successful against the specified model

    Args:
        gen_str (str): Generated model output
        test_prefixes (list): List of test prefixes

    Returns:
        Tuple:
            Boolean of whether the model jailbreak was successful
            Generated string
    """
    gen_str = gen_str.lower()
    jailbreak = False
    lowercase_test_prefixes = [word.lower() for word in test_prefixes]
    # This only checks for known rejections -- the model output may still not achieve the goal.
    # TODO: Use a better detector
    if len(gen_str) != 0:
        jailbreak = not any([prefix in gen_str for prefix in lowercase_test_prefixes])
    return jailbreak


def load_conversation_template(template_name: str):
    """Load the specified conversation template

    Args:
        template_name (str): template name to load from fastchat

    Returns:
        Conversation template
    """
    try:
        conv_template = fsmodel.get_conversation_template(template_name)
        if conv_template.name == "zero_shot":
            conv_template.roles = tuple(["### " + r for r in conv_template.roles])
            conv_template.sep = "\n"
        elif conv_template.name == "llama-2":
            conv_template.sep2 = conv_template.sep2.strip()
        return conv_template
    except Exception as e:
        logger.error(e)


class AutoDanPrefixManager:
    def __init__(self, *, generator, conv_template, instruction, target, adv_string):
        """Prefix manager class for AutoDAN

        Args:
            generator (garak.generators.huggingface.Model): Generator to use
            conv_template (ConversationTemplate): Conversation template for specified model
            instruction (str): Instruction to pass to the model
            target (str): Target output string
            adv_string (str): Adversarial (jailbreak) string
        """

        self.tokenizer = generator.tokenizer
        self.conv_template = conv_template
        self.instruction = instruction
        self.target = target
        self.adv_string = adv_string

    def get_prompt(self, adv_string=None):
        if adv_string is not None:
            self.adv_string = adv_string

        self.conv_template.append_message(
            self.conv_template.roles[0], f"{self.adv_string} {self.instruction} "
        )
        self.conv_template.append_message(self.conv_template.roles[1], f"{self.target}")
        prompt = self.conv_template.get_prompt()

        encoding = self.tokenizer(prompt)

        if self.conv_template.name == "llama-2":
            self.conv_template.messages = []

            self.conv_template.append_message(self.conv_template.roles[0], None)
            toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
            self._user_role_slice = slice(None, len(toks))

            self.conv_template.update_last_message(f"{self.instruction}")
            toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
            self._goal_slice = slice(
                self._user_role_slice.stop, max(self._user_role_slice.stop, len(toks))
            )

            separator = " " if self.instruction else ""
            self.conv_template.update_last_message(
                f"{self.adv_string}{separator}{self.instruction}"
            )
            toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
            self._control_slice = slice(self._goal_slice.stop, len(toks))

            self.conv_template.append_message(self.conv_template.roles[1], None)
            toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
            self._assistant_role_slice = slice(self._control_slice.stop, len(toks))

            self.conv_template.update_last_message(f"{self.target}")
            toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
            self._target_slice = slice(self._assistant_role_slice.stop, len(toks) - 2)
            self._loss_slice = slice(self._assistant_role_slice.stop - 1, len(toks) - 3)

        # This needs improvement
        else:
            python_tokenizer = False or self.conv_template.name == "oasst_pythia"
            try:
                encoding.char_to_token(len(prompt) - 1)
            except:
                python_tokenizer = True

            if python_tokenizer:
                # This is specific to the vicuna and pythia tokenizer and conversation prompt.
                # It will not work with other tokenizers or prompts.
                self.conv_template.messages = []

                self.conv_template.append_message(self.conv_template.roles[0], None)
                toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
                self._user_role_slice = slice(None, len(toks))

                self.conv_template.update_last_message(f"{self.instruction}")
                toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
                self._goal_slice = slice(
                    self._user_role_slice.stop,
                    max(self._user_role_slice.stop, len(toks) - 1),
                )

                separator = " " if self.instruction else ""
                self.conv_template.update_last_message(
                    f"{self.adv_string}{separator}{self.instruction}"
                )
                toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
                self._control_slice = slice(self._goal_slice.stop, len(toks) - 1)

                self.conv_template.append_message(self.conv_template.roles[1], None)
                toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
                self._assistant_role_slice = slice(self._control_slice.stop, len(toks))

                self.conv_template.update_last_message(f"{self.target}")
                toks = self.tokenizer(self.conv_template.get_prompt()).input_ids
                self._target_slice = slice(
                    self._assistant_role_slice.stop, len(toks) - 1
                )
                self._loss_slice = slice(
                    self._assistant_role_slice.stop - 1, len(toks) - 2
                )
            else:
                self._system_slice = slice(
                    None, encoding.char_to_token(len(self.conv_template.system_message))
                )
                self._user_role_slice = slice(
                    encoding.char_to_token(prompt.find(self.conv_template.roles[0])),
                    encoding.char_to_token(
                        prompt.find(self.conv_template.roles[0])
                        + len(self.conv_template.roles[0])
                        + 1
                    ),
                )
                self._goal_slice = slice(
                    encoding.char_to_token(prompt.find(self.instruction)),
                    encoding.char_to_token(
                        prompt.find(self.instruction) + len(self.instruction)
                    ),
                )
                self._control_slice = slice(
                    encoding.char_to_token(prompt.find(self.adv_string)),
                    encoding.char_to_token(
                        prompt.find(self.adv_string) + len(self.adv_string)
                    ),
                )
                self._assistant_role_slice = slice(
                    encoding.char_to_token(prompt.find(self.conv_template.roles[1])),
                    encoding.char_to_token(
                        prompt.find(self.conv_template.roles[1])
                        + len(self.conv_template.roles[1])
                        + 1
                    ),
                )
                self._target_slice = slice(
                    encoding.char_to_token(prompt.find(self.target)),
                    encoding.char_to_token(prompt.find(self.target) + len(self.target)),
                )
                self._loss_slice = slice(
                    encoding.char_to_token(prompt.find(self.target)) - 1,
                    encoding.char_to_token(prompt.find(self.target) + len(self.target))
                    - 1,
                )

        self.conv_template.messages = []

        return prompt

    def get_input_ids(self, adv_string=None):
        """Get input ids from the tokenizer for a provided string

        Args:
            adv_string (str): String to tokenize

        Returns:
            Torch tensor of input_ids
        """
        prompt = self.get_prompt(adv_string=adv_string)
        toks = self.tokenizer(prompt).input_ids
        input_ids = torch.tensor(toks[: self._target_slice.stop])

        return input_ids
