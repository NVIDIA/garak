# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration, _plugin


class RenameMitigationBypass(Migration):
    """Migrate configurations to the keyword-based detector's new name."""

    def apply(config_dict: dict) -> dict:
        """Rename mitigation.MitigationBypass to MitigationBypassKW."""

        path = ["plugins", "detectors", "mitigation"]
        return _plugin.rename(
            config_dict,
            path,
            "MitigationBypass",
            "MitigationBypassKW",
        )
