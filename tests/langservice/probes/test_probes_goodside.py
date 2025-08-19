# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from garak import _config, _plugins
from garak.probes.goodside import Tag
import json


PROBES = [
    classname
    for (classname, _) in _plugins.enumerate_plugins("probes")
    if "goodside" in classname
]


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_Tag_attempt_descrs_translation(mocker):
    import garak.langservice
    from garak.langproviders.local import Passthru, LocalHFTranslator

    mock_translator_return = mocker.patch.object(garak.langservice, "get_langprovider")

    mock_translator_return.side_effect = [
        Passthru(
            {
                "langproviders": {
                    "local": {
                        "language": "en,jap",
                    }
                }
            }
        ),  # First default lang probe forward
        Passthru(
            {
                "langproviders": {
                    "local": {
                        "language": "en,jap",
                    }
                }
            }
        ),  # First default lang probe reverse
        LocalHFTranslator(  # Second translated lang probe forward
            {
                "langproviders": {
                    "local": {
                        "language": "en,jap",
                        "model_type": "local",
                    }
                }
            }
        ),
        LocalHFTranslator(  # Second translated lang probe reverse
            {
                "langproviders": {
                    "local": {
                        "language": "jap,en",
                        "model_type": "local",
                    }
                }
            }
        ),
    ]
    # default language probe
    probe_tag_en = Tag(_config)
    probe_tag_jap = Tag(_config)

    attempt_descrs = probe_tag_en.attempt_descrs
    output_attempt_descrs = probe_tag_jap.attempt_descrs

    for i in range(len(attempt_descrs)):

        convert_translated_attempt_descrs = json.loads(
            probe_tag_jap._convert_json_string(output_attempt_descrs[i])
        )
        convert_descr = json.loads(
            probe_tag_jap._convert_json_string(attempt_descrs[i])
        )
        if convert_descr["prompt_stub"] != [""]:
            assert (
                convert_descr["prompt_stub"]
                != convert_translated_attempt_descrs["prompt_stub"]
            ), "Prompt stub should be translated"
        if convert_descr["payload"] != "":
            assert (
                convert_descr["payload"] != convert_translated_attempt_descrs["payload"]
            ), "Payload should be translated"
