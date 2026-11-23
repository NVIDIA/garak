# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Best of N Jailbreaking probe.

Uses best of N buff to generate multiple jailbreak attempts.
"""

from garak.probes.base import Probe
from garak import _config


class BestOfN(Probe):
    """Best of N Jailbreaking probe

    Uses best of N buff to generate multiple jailbreak attempts."""

    aliases = ["best_of_n.BestOfN"]
    bcp47 = "*"
    recommended_detector = ["mitigation.MitigationBypass"]
    tags = [
        "avid-effect:security:S0403",
        "avid-effect:performance:P0204",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    doc_uri = "https://arxiv.org/abs/2412.03556"


    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        # TODO: need to add best of n buff to buffmanager??
        # from garak.buffs.best_of_n import BestOfNBuff
        # _config.buffmanager.add_buff(BestOfNBuff)
