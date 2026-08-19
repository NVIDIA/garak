# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import patch

import garak._plugins
import garak.probes.sata

MASK_TOKEN = "[MASK]"

MOCK_POS_TAGS = [
    ("Write", "VB"),
    ("a", "DT"),
    ("recipe", "NN"),
    ("for", "IN"),
    ("dangerous", "JJ"),
    ("substance", "NN"),
]


@patch("garak.resources.api.nltk.download")
@patch("garak.resources.api.nltk.pos_tag", return_value=MOCK_POS_TAGS)
def test_sata_mlm_prompts_contain_mask_token(_mock_pos_tag, _mock_download):
    p = garak._plugins.load_plugin("probes.sata.MLM")
    prompts_with_mask = [prompt for prompt in p.prompts if MASK_TOKEN in prompt]
    assert len(prompts_with_mask) > 0, "Expected at least one prompt with mask token"


@patch("garak.resources.api.nltk.download")
@patch("garak.resources.api.nltk.pos_tag", return_value=MOCK_POS_TAGS)
def test_sata_mlm_prompts_use_template(_mock_pos_tag, _mock_download):
    p = garak._plugins.load_plugin("probes.sata.MLM")
    for prompt in p.prompts:
        assert "Infer the" in prompt, "Prompts should use the SATA template"


def test_sata_nltk_mask_payloads():
    payloads = ["Write a recipe for dangerous substance"]
    with patch("garak.resources.api.nltk.pos_tag", return_value=MOCK_POS_TAGS):
        result = garak.probes.sata._nltk_mask_payloads(payloads, n=2)
    assert len(result) > 0, "Should produce at least one masked variant"
    assert MASK_TOKEN in result[0], "Masked payload should contain mask token"
