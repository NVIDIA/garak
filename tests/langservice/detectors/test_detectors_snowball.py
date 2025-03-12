import pytest
import os
import pathlib

from garak.attempt import Attempt
from garak import _config
from garak.detectors.snowball import DontStartNo, DontStartYes


@pytest.fixture
def dont_start_no_detector():
    local_config_path = str(
        pathlib.Path(__file__).parents[1] / "test_config" / "translation.yaml"
    )
    if os.path.exists(local_config_path) is False:
        pytest.skip("Local config file does not exist, skipping test.")
    _config.load_config(run_config_filename=local_config_path)
    translator_config = {
        "language": "en-ja",
        "model_type": "local",
        "model_name": "facebook/m2m100_418M",
    }
    reverse_translator_config = {
        "language": "ja-en",
        "model_type": "local",
        "model_name": "facebook/m2m100_418M",
    }
    _config.run.translators.append(translator_config)
    _config.run.translators.append(reverse_translator_config)
    _config.run.target_lang = "ja"
    detector = DontStartNo(_config)
    return detector


@pytest.fixture
def dont_start_yes_detector():
    local_config_path = str(
        pathlib.Path(__file__).parents[1] / "test_config" / "translation.yaml"
    )
    if os.path.exists(local_config_path) is False:
        pytest.skip("Local config file does not exist, skipping test.")
    _config.load_config(run_config_filename=local_config_path)
    translator_config = {
        "language": "en-ja",
        "model_type": "local",
        "model_name": "facebook/m2m100_418M",
    }
    reverse_translator_config = {
        "language": "ja-en",
        "model_type": "local",
        "model_name": "facebook/m2m100_418M",
    }
    _config.run.translators.append(translator_config)
    _config.run.translators.append(reverse_translator_config)
    _config.run.target_lang = "ja"
    detector = DontStartYes(_config)
    return detector


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_dont_start_no_reverse_translation(dont_start_no_detector):
    attempt = Attempt(prompt="PLACEHOLDER", bcp47="ja")
    attempt.outputs = [
        "いいえ、それはしません。",  # "No, it doesn't." in Japanese
        "確かにそうです。",  # "Yes, it does." in Japanese
    ]
    attempt.reverse_translator_outputs = (
        dont_start_no_detector.reverse_translator.translate_prompts(attempt.all_outputs)
    )

    results = dont_start_no_detector.detect(attempt)
    assert results == [
        1.0,
        0.0,
    ], "Reverse translation results do not match expected values for DontStartNo"


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_dont_start_yes_reverse_translation(dont_start_yes_detector):
    attempt = Attempt(prompt="PLACEHOLDER", bcp47="ja")
    attempt.outputs = [
        "はい、それはします。",  # "Yes, it does." in Japanese
        "いいえ、それはしません。",  # "No, it doesn't." in Japanese
    ]
    attempt.reverse_translator_outputs = (
        dont_start_yes_detector.reverse_translator.translate_prompts(
            attempt.all_outputs
        )
    )

    results = dont_start_yes_detector.detect(attempt)
    assert results == [
        1.0,
        0.0,
    ], "Reverse translation results do not match expected values for DontStartYes"
