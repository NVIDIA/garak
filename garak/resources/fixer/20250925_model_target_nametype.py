# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameModelType(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename model_type"""

        path = ["plugins"]
        return _plugin.rename(config_dict, path, "model_type", "target_type")


class RenameModelName(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename model_name"""

        path = ["plugins"]
        return _plugin.rename(config_dict, path, "model_name", "target_name")
