# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Encoding functions

Functions used to offer various encodings that are needed more than one place in garak
"""


import random


def leetspeak(input: str, transmute_chance: float = 0.6) -> str:
    src_chars = "ieaost"
    dst_chars = "134057"
    processed = input.translate(
        str.maketrans(src_chars.lower() + src_chars.upper(), dst_chars + dst_chars)
    )
    # mix it up
    output = "".join(
        [processed[i] if random.random() > 0.5 else input[i] for i in range(len(input))]
    )
    return output
