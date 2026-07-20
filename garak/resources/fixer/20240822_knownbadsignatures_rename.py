# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameKnownbadsignatures(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename probe family knownbadsignatures -> av_spam_scanning"""

        path = ["plugins", "probes"]
        old = "knownbadsignatures"
        new = "av_spam_scanning"
        return _plugin.rename(config_dict, path, old, new)
