# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameContinuation(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename continuation probe class 80 -> Mini"""

        path = ["plugins", "probes", "continuation"]
        old = "ContinueSlursReclaimedSlurs80"
        new = "ContinueSlursReclaimedSlursMini"
        return _plugin.rename(config_dict, path, old, new)
