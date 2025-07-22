# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


# commented out pending required functionality in fixer
"""
class RenameSpecialwords(Migration):
    def apply(config_dict: dict) -> dict:
        # Rename ex-specialwords detectors to their landing places

        path = ["plugins", "detectors"]
        renames = (
            ["specialwords.SlursReclaimedSlurs", "unsafe_content.SlursReclaimedSlurs"],
            ["specialwords.Prefixes", "mitigation.Prefixes"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config
"""