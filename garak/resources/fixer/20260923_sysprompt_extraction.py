# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Migrate the aggregate system-prompt extraction probe to technique probes."""

from garak.resources.fixer import Migration, _plugin

_OLD_SYSTEM_PROMPT_EXTRACTION_PROBE = (
    "probes.sysprompt_extraction.SystemPromptExtraction"
)
_SYSTEM_PROMPT_EXTRACTION_PROBES = (
    "probes.sysprompt_extraction.DirectRequests",
    "probes.sysprompt_extraction.RolePlayingClaimAuthority",
    "probes.sysprompt_extraction.WorldBuildingScenarios",
    "probes.sysprompt_extraction.RolePlayingTargetPersona",
    "probes.sysprompt_extraction.EncodingBasedAttacks",
    "probes.sysprompt_extraction.IgnorePreviousInstructions",
    "probes.sysprompt_extraction.PerspectiveShifting",
    "probes.sysprompt_extraction.Programming",
    "probes.sysprompt_extraction.GiveExamples",
    "probes.sysprompt_extraction.StrongArmScenarios",
    "probes.sysprompt_extraction.StrongArmClaimAuthority",
)


class SplitSystemPromptExtraction(Migration):
    """Replace the aggregate probe with its technique-specific probes."""

    @staticmethod
    def apply(config_dict: dict) -> dict:
        return _plugin.rename_v2(
            config_dict,
            _OLD_SYSTEM_PROMPT_EXTRACTION_PROBE,
            _SYSTEM_PROMPT_EXTRACTION_PROBES,
        )
