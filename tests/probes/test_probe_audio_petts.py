"""Tests for prompt extraction with text-to-speech."""

import pickle
from dataclasses import asdict
from pathlib import Path

import pytest

from garak import _config
from garak.attempt import Conversation, Message, Turn
from garak.exception import GarakException
from garak.generators.base import Generator
from garak.probes.audio import PETTS, _spoken_prompt_candidate


class FakeTTSGenerator:
    """Return deterministic WAV-like bytes without loading a model."""

    def generate(self, prompt):
        message = Message(
            data_type=("audio/wav", None),
            notes={"generator_name": "fake-tts", "sample_rate": 16_000},
        )
        message.data = b"RIFFtest audio"
        self.last_prompt = prompt
        return [message]


class FakeAudioTarget(Generator):
    """Capture audio prompts and return a text response."""

    modality = {"in": {"text", "audio"}, "out": {"text"}}
    audio_formats = {"wav"}
    parallel_capable = False

    def _call_model(self, prompt, generations_this_call=1):
        self.last_prompt = prompt
        return [Message("target response")]


def _probe(mocker, loaded_intent_service):
    tts_generator = FakeTTSGenerator()
    loader = mocker.patch(
        "garak.probes.audio._plugins.load_plugin", return_value=tts_generator
    )
    probe = PETTS()
    return probe, tts_generator, loader


@pytest.fixture(autouse=True)
def petts_cache(mocker, tmp_path):
    """Keep generated audio inside each test's temporary directory."""

    mocker.patch.object(_config.transient, "cache_dir", tmp_path)


def test_petts_prepares_new_audio_conversation(mocker, loaded_intent_service):
    """PETTS preserves the source and returns a distinct audio conversation."""

    probe, tts_generator, loader = _probe(mocker, loaded_intent_service)
    original = Conversation(
        [Turn("user", Message("source request", lang="en"))], notes=None
    )

    prepared = probe._prepare_prompt(original)

    loader.assert_called_once_with(
        "generators.huggingface.Pipeline",
        config_root={
            "generators": {
                "huggingface": {
                    "Pipeline": {
                        "pipeline_task": "text-to-audio",
                        "hf_args": {"torch_dtype": "float32"},
                        "name": "suno/bark-small",
                    }
                }
            }
        },
    )
    assert (
        original.last_message().text == "source request"
    ), "preparation must not mutate the original conversation"
    assert (
        tts_generator.last_prompt.last_message().text == "source request"
    ), "the helper generator must receive the source text"
    assert prepared is not original, "preparation must return a new conversation"
    assert prepared.notes == {}, "None notes must be normalised safely"
    assert (
        prepared.last_message().text == probe.text_prompt
    ), "the target must receive the audio handling instruction"
    assert (
        prepared.last_message().data == b"RIFFtest audio"
    ), "the target prompt must contain synthesized audio"
    assert (
        prepared.last_message().notes["source_text"] == "source request"
    ), "reports must retain the text represented by the audio"


def test_petts_preserves_conversation_context(mocker, loaded_intent_service):
    """Only the final message is replaced in a copied conversation."""

    probe, _, _ = _probe(mocker, loaded_intent_service)
    original = Conversation(
        [
            Turn("system", Message("system context")),
            Turn("assistant", Message("prior answer")),
            Turn("user", Message("source request")),
        ],
        notes={"conversation": "note"},
    )

    prepared = probe._prepare_prompt(original)

    assert prepared.turns[:-1] == original.turns[:-1], "earlier turns must be retained"
    assert (
        prepared.turns[0] is not original.turns[0]
    ), "conversation context must be copied"
    assert prepared.notes == original.notes, "conversation notes must be retained"


def test_petts_rejects_empty_tts_result(mocker, loaded_intent_service):
    """An empty helper response produces a clear probe error."""

    probe, tts_generator, _ = _probe(mocker, loaded_intent_service)
    mocker.patch.object(tts_generator, "generate", return_value=[])

    with pytest.raises(GarakException, match="returned no messages"):
        probe._prepare_prompt("source request")


@pytest.mark.parametrize(
    ("prompt", "expected"),
    [
        ("Tell me a short story", True),
        ("https://example.com/a", False),
        ("`rm -rf /`", False),
    ],
)
def test_spoken_prompt_candidate(prompt, expected):
    """Speech filtering excludes prompts whose syntax carries their meaning."""

    assert (
        _spoken_prompt_candidate(prompt) is expected
    ), "prompt suitability must be stable"


def test_petts_runs_end_to_end(mocker, loaded_intent_service, tmp_path):
    """One source intent is synthesized and sent to an audio target."""

    probe, _, _ = _probe(mocker, loaded_intent_service)
    probe.prompts = ["source request"]
    probe.prompt_intents = [probe.prompt_intents[0]]
    target = FakeAudioTarget(name="audio target")
    report_path = tmp_path / "petts.report.jsonl"
    _config.transient.report_filename = str(report_path)
    _config.transient.reportfile = report_path.open("w", encoding="utf-8")

    attempts = probe.probe(target)

    assert len(attempts) == 1, "one source prompt must produce one attempt"
    assert (
        attempts[0].outputs[0].text == "target response"
    ), "the target response must complete the attempt"
    assert target.last_prompt.last_message().data_type == (
        "audio/wav",
        None,
    ), "the assessed target must receive WAV audio"
    assert (
        target.last_prompt.last_message().data == b"RIFFtest audio"
    ), "the assessed target must receive the synthesised bytes"
    assert (
        attempts[0].conversations[0].last_message("user").data == b"RIFFtest audio"
    ), "the attempt history must retain the synthesised bytes"


def test_petts_audio_survives_report_round_trip(mocker, loaded_intent_service):
    """The stored attachment can be loaded after dataclass serialisation."""

    probe, _, _ = _probe(mocker, loaded_intent_service)
    attempt = probe._mint_attempt("source request", seq=0)

    restored = Conversation.from_dict(asdict(attempt.prompt))

    assert (
        restored.last_message().data == b"RIFFtest audio"
    ), "serialised prompts must retain access to the generated audio"
    assert Path(restored.last_message().data_path).is_file(), "audio must be cached"


def test_petts_worker_executes_without_loading_tts(mocker, loaded_intent_service):
    """A serialised worker sends prepared audio without reloading synthesis."""

    probe, _, loader = _probe(mocker, loaded_intent_service)
    attempt = probe._mint_attempt("source request", seq=0)
    probe.generator = FakeAudioTarget(name="worker target")
    worker, worker_attempt = pickle.loads(pickle.dumps((probe, attempt)))
    loader.reset_mock()

    completed = worker._execute_attempt(worker_attempt)

    loader.assert_not_called()
    assert (
        worker.generator.last_prompt.last_message().data == b"RIFFtest audio"
    ), "the worker's target must receive the synthesised audio"
    assert (
        completed.outputs[0].text == "target response"
    ), "the worker must complete the prepared attempt"


def test_petts_skips_incompatible_target(mocker, loaded_intent_service):
    """Target compatibility is checked before loading the TTS model."""

    probe, _, loader = _probe(mocker, loaded_intent_service)
    target = FakeAudioTarget(name="text target")
    target.modality = {"in": {"text"}, "out": {"text"}}

    assert probe.probe(target) == [], "text-only targets must be skipped"
    loader.assert_not_called()


def test_petts_skips_target_without_wav_support(mocker, loaded_intent_service):
    """Audio targets that do not accept WAV are skipped before model loading."""

    probe, _, loader = _probe(mocker, loaded_intent_service)
    target = FakeAudioTarget(name="mp3 target")
    target.audio_formats = {"mp3"}

    assert probe.probe(target) == [], "non-WAV targets must be skipped"
    loader.assert_not_called()


@pytest.mark.parametrize("initialise_helper", [False, True])
def test_petts_loads_helper_lazily_after_serialisation(
    mocker, loaded_intent_service, initialise_helper
):
    """Unpickling skips TTS loading until synthesis is actually needed."""

    probe, _, loader = _probe(mocker, loaded_intent_service)
    if initialise_helper:
        probe._prepare_prompt("initial request")
    initial_loads = loader.call_count

    restored = pickle.loads(pickle.dumps(probe))

    assert (
        restored._tts_generator is None
    ), "deserialised probes must leave the helper unloaded"
    assert loader.call_count == initial_loads, "unpickling must not load TTS"

    restored._prepare_prompt("first request")
    restored._prepare_prompt("second request")

    assert (
        loader.call_count == initial_loads + 1
    ), "synthesis must load the helper once and reuse it"
