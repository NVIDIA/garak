# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Modelling of attack intents, i.e. the behaviour an attack tries to elicit
from the target"""

class Intent():
    key: None
    descriptions: None
    sub_intents: None

    def __init__(self) -> None:
        pass