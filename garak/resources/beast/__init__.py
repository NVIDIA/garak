# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Implementation of BEAST attack from Sadasivan et al. "Fast Adversarial Attacks on Language Models In One GPU Minute" (https://arxiv.org/abs/2402.15570v1)

Code derived from paper, with help from the official implementation:
https://github.com/vinusankars/BEAST?tab=readme-ov-file

Considerable inspiration was drawn from Dreadnode's implementation:
https://github.com/dreadnode/research/blob/main/notebooks/Mistral%20-%20BEAST%20Beam%20Attack.ipynb
"""

from garak.resources.beast.beast_attack import run_beast
