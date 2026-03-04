# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
This module implements the Tree of Attacks with Pruning (TAP) attack methodology developed by Mehrota et al.
in the Tree of Attacks paper (https://arxiv.org/abs/2312.02119)
TAP is a generalization of Prompt Automatic Iterative Refinement (PAIR) as described by Chao et al. in the paper
Jailbreaking Black Box Large Language Models in Twenty Queries (https://arxiv.org/abs/2310.08419)

The PAIR method can be used by setting `branching_factor=1` and `pruning=False` in the generate_tap function.

Some of the code in this module is derived from Robust Intelligence's implementation: https://github.com/RICommunity/TAP
"""

from .tap_main import run_tap
