# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameXSS(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename probe family xss -> web_injection"""

        updated_config = config_dict

        path = ["plugins", "probes"]
        old = "xss"
        new = "web_injection"
        updated_config = _plugin.rename(updated_config, path, old, new)

        path = ["plugins", "probes", "web_injection"]
        old = "MdExfil20230929"
        new = "PlaygroundMarkdownExfil"
        updated_config = _plugin.rename(updated_config, path, old, new)

        path = ["plugins", "detectors"]
        old = "xss"
        new = "web_injection"
        updated_config = _plugin.rename(updated_config, path, old, new)

        path = ["plugins", "detectors", "web_injection"]
        old = "MarkdownExfil20230929"
        new = "PlaygroundMarkdownExfil"

        return _plugin.rename(updated_config, path, old, new)
