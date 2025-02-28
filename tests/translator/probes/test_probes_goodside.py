import pytest
from garak import _config, _plugins
from garak.probes.goodside import Tag
from garak.translators.base import convert_json_string
import json


PROBES = [
    classname
    for (classname, _) in _plugins.enumerate_plugins("probes")
    if "goodside" in classname
]


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_Tag_attempt_descrs_translation(mocker):
    import garak.translator
    from garak.translators.local import NullTranslator, LocalHFTranslator

    mock_translator_return = mocker.patch.object(garak.translator, "get_translator")

    mock_translator_return.side_effect = [
        NullTranslator(),  # First default lang probe forward
        NullTranslator(),  # First default lang probe reverse
        LocalHFTranslator(  # Second translated lang probe forward
            {
                "translators": {
                    "local": {
                        "language": "en-jap",
                        "model_type": "local",
                        "model_name": "Helsinki-NLP/opus-mt-{}",
                    }
                }
            }
        ),
        LocalHFTranslator(  # Second translated lang probe reverse
            {
                "translators": {
                    "local": {
                        "language": "jap-en",
                        "model_type": "local",
                        "model_name": "Helsinki-NLP/opus-mt-{}",
                    }
                }
            }
        ),
    ]
    # default language probe
    probe_tag_en = Tag(_config)
    probe_tag_jap = Tag(_config)

    attempt_descrs = probe_tag_en.attempt_descrs
    translated_attempt_descrs = probe_tag_jap.attempt_descrs

    for i in range(len(attempt_descrs)):

        convert_translated_attempt_descrs = json.loads(
            convert_json_string(translated_attempt_descrs[i])
        )
        convert_descr = json.loads(convert_json_string(attempt_descrs[i]))
        if convert_descr["prompt_stub"] != [""]:
            assert (
                convert_descr["prompt_stub"]
                != convert_translated_attempt_descrs["prompt_stub"]
            ), "Prompt stub should be translated"
        if convert_descr["payload"] != "":
            assert (
                convert_descr["payload"] != convert_translated_attempt_descrs["payload"]
            ), "Payload should be translated"
