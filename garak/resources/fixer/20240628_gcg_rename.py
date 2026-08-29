# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameGCG(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename probe family gcg -> suffix"""

        path = ["plugins", "probes"]
        old = "gcg"
        new = "suffix"
        return _plugin.rename(config_dict, path, old, new)
