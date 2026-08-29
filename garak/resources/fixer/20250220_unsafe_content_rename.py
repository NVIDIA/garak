# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameRiskywords(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename probe family riskywords -> unsafe_content"""

        path = ["plugins", "probes"]
        old = "riskywords"
        new = "unsafe_content"
        return _plugin.rename(config_dict, path, old, new)


class RenameToxicity(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename probe family toxicity -> unsafe_content"""

        path = ["plugins", "probes"]
        old = "toxicity"
        new = "unsafe_content"
        return _plugin.rename(config_dict, path, old, new)
