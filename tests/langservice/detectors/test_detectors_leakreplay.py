import pytest
import os
import pathlib

from garak import _config
from garak.attempt import Attempt
from garak.detectors.leakreplay import StartsWith


@pytest.fixture
def detector_start_with():
    local_config_path = str(
        pathlib.Path(__file__).parents[1] / "test_config" / "translation_local_low.yaml"
    )
    if os.path.exists(local_config_path) is False:
        pytest.skip("Local config file does not exist, skipping test.")
    _config.load_config(run_config_filename=local_config_path)
    translator_config = {
        "language": "en-jap",
        "model_type": "local",
        "model_name": "Helsinki-NLP/opus-mt-{}",
    }
    reverse_translator_config = {
        "language": "jap-en",
        "model_type": "local",
        "model_name": "Helsinki-NLP/opus-mt-{}",
    }
    _config.run.translators.append(translator_config)
    _config.run.translators.append(reverse_translator_config)
    _config.run.target_lang = "jap"
    detector = StartsWith(_config)
    return detector


def detector_reverse_translate(detector, attempt) -> Attempt:
    reverse_translator = detector.get_reverse_translator()
    for i, thread in enumerate(attempt.messages):
        for j, turn in enumerate(thread):
            if turn["role"] == "assistant":
                attempt.messages[i][j]["content"] = "\n".join(
                    reverse_translator.translate_prompts(turn["content"].split("\n"))
                )
    return attempt


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_startswith_detect(detector_start_with):
    detector = detector_start_with

    attempt = Attempt(prompt="This is a test prompt")
    attempt.notes["triggers"] = ["Hello", "Test"]
    attempt.outputs = [
        "Hello world",
        "This is a test",
        "Test case",
        "No match here",
        "陰府 の 端 に は 陰府 の 穴 が あ る.",
    ]

    # Run the detection
    results = detector.detect(attempt)
    attempt = detector_reverse_translate(detector, attempt)

    # Verify the results
    assert isinstance(results, list), "Detect method should return a list"
    assert len(results) == len(
        attempt.all_outputs
    ), "Results should match the number of outputs"
    assert results == [
        1.0,
        0.0,
        1.0,
        0.0,
        0.0,
    ], "Detection results do not match expected values"
