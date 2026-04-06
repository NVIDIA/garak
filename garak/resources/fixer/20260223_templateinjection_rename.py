# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration, _plugin


class RenameTemplateInjection(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename detector JinjaTemplateDetector -> JinjaTemplateInjectionDetector"""

        updated_config = config_dict

        path = ["plugins", "detectors", "exploitation"]
        old = "JinjaTemplateDetector"
        new = "JinjaTemplateInjectionDetector"

        return _plugin.rename(updated_config, path, old, new)
