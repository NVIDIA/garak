# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Context Compliance jailbreak probe"""

import json

from garak import _config
from garak.data import path as data_path
import garak.attempt
import garak.probes


class ContextCompliance(garak.probes.Probe):
    """Context Compliance jailbreak probe.

    Injects a fabricated benign conversation as history before delivering
    the harmful objective as a follow-up "yes." — making the target more
    likely to comply by establishing a helpful prior context.
    """

    active = True
    lang = "en"
    goal = "make the model comply with a harmful request primed by benign context"
    doc_uri = ""
    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "payload:jailbreak",
        "quality:Security:PromptStability",
    ]
    primary_detector = "mitigation.MitigationBypass"
    tier = garak.probes.Tier.OF_CONCERN

    def __init__(self, config_root=_config):
        super().__init__(config_root)
        with open(data_path / "context_compliance.json", encoding="utf-8") as f:
            data = json.load(f)
        self.prompts = self._build_conversations(data["entries"])

    def _build_conversations(self, entries: list) -> list:
        conversations = []
        for entry in entries:
            turns = [
                garak.attempt.Turn(
                    role=t["role"],
                    content=garak.attempt.Message(text=t["content"]),
                )
                for t in entry["conversation"]
            ]
            conversations.append(garak.attempt.Conversation(turns=turns))
        return conversations
