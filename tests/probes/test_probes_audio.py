# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import tempfile

import pytest

from garak import _config, _plugins
from garak.attempt import Message
import garak.probes.audio
import garak.services.intentservice


@pytest.fixture()
def petts_probe(monkeypatch, tmp_path) -> garak.probes.audio.PETTS:
    _config.load_config()
    _config.cas.intent_spec = "S"
    _config.cas.serve_detectorless_intents = True
    monkeypatch.setattr(_config.transient, "cache_dir", tmp_path)
    temp_report_file = tempfile.NamedTemporaryFile(
        mode="w+", delete=False, encoding="utf-8"
    )
    monkeypatch.setattr(_config.transient, "reportfile", temp_report_file)
    monkeypatch.setattr(_config.transient, "report_filename", temp_report_file.name)
    monkeypatch.setattr(garak.probes.audio, "_spoken_prompt_candidate", lambda _: True)
    garak.services.intentservice.load()
    yield garak.probes.audio.PETTS()
    temp_report_file.close()


def test_petts_ensure_audio_file_writes_to_cache(petts_probe, monkeypatch):
    synthesis_calls = []

    def fake_synthesise(prompt_text: str, audio_path: Path) -> None:
        synthesis_calls.append((prompt_text, audio_path))
        audio_path.write_bytes(b"RIFF....WAVEfmt ")

    monkeypatch.setattr(petts_probe, "_synthesise_audio", fake_synthesise)

    audio_path = petts_probe._ensure_audio_file("Describe safe behaviour.")
    assert (
        audio_path.parent == petts_probe.audio_cache_dir
    ), "writes generated audio into its cache directory"
    assert audio_path.exists(), "creates an audio cache file on first use"
    assert len(synthesis_calls) == 1, "synthesises uncached audio once"

    cached_audio_path = petts_probe._ensure_audio_file("Describe safe behaviour.")
    assert (
        cached_audio_path == audio_path
    ), "returns the same cache path for the same prompt and config"
    assert len(synthesis_calls) == 1, "reuses cached audio without re-synthesising"


def test_petts_audio_format_is_configurable(petts_probe):
    petts_probe.tts_audio_format = "OGG"
    petts_probe.tts_audio_subtype = "VORBIS"
    configured_audio_path = petts_probe._audio_file_path("Describe safe behaviour.")

    assert (
        configured_audio_path.suffix == ".ogg"
    ), "uses the configured audio format in cache filenames"


def test_petts_spoken_prompt_candidate_filter():
    assert garak.probes.audio._spoken_prompt_candidate(
        "Please explain how this request works."
    ), "accepts natural-language spoken candidates"
    assert not garak.probes.audio._spoken_prompt_candidate(
        ""
    ), "rejects empty spoken candidates"
    assert not garak.probes.audio._spoken_prompt_candidate(
        "Read https://example.com before answering."
    ), "rejects URL-bearing spoken candidates"
    assert not garak.probes.audio._spoken_prompt_candidate(
        "Run `rm -rf /tmp/example` now."
    ), "rejects code-like spoken candidates"


def test_petts_mp3_and_stereo_affect_cache_path(petts_probe):
    petts_probe.tts_audio_format = "MP3"
    petts_probe.tts_audio_stereo = False

    mono_audio_path = petts_probe._audio_file_path("Describe safe behaviour.")
    assert (
        mono_audio_path.suffix == ".mp3"
    ), "uses MP3 cache suffix when MP3 is configured"
    assert petts_probe._audio_subtype() is None, "does not force PCM subtype for MP3"

    petts_probe.tts_audio_stereo = True
    stereo_audio_path = petts_probe._audio_file_path("Describe safe behaviour.")

    assert stereo_audio_path.suffix == ".mp3", "preserves MP3 suffix for stereo output"
    assert stereo_audio_path != mono_audio_path, "caches mono and stereo separately"


def test_petts_probe_skips_incompatible_audio_format(petts_probe, monkeypatch):
    generator = _plugins.load_plugin("generators.test.Repeat")
    monkeypatch.setattr(generator, "modality", {"in": {"text", "audio"}})
    monkeypatch.setattr(generator, "supported_audio_formats", {"mp3"}, raising=False)
    petts_probe.tts_audio_format = "WAV"

    assert petts_probe.probe(generator) == [], "skips unsupported audio format"


def test_petts_stereo_config_must_be_bool(petts_probe):
    petts_probe.tts_audio_stereo = "stereo"
    with pytest.raises(ValueError, match="tts_audio_stereo"):
        petts_probe._apply_audio_channels([0.0, 0.1])


def test_petts_audio_prompt_preparation_skips_failed_prompt(petts_probe, monkeypatch):
    def fake_synthesise(prompt_text: str, audio_path: Path) -> None:
        if prompt_text == "skip this one":
            raise RuntimeError("tts failed")
        audio_path.write_bytes(b"RIFF....WAVEfmt ")

    monkeypatch.setattr(petts_probe, "_synthesise_audio", fake_synthesise)
    petts_probe.audio_source_prompts = [
        "keep this one",
        "skip this one",
        "keep this too",
    ]
    petts_probe.prompt_intents = ["S001", "S002", "S003"]

    prompts = petts_probe._audio_prompts()

    assert len(prompts) == 2, "skips only failed audio preparations"
    assert petts_probe.prompt_intents == [
        "S001",
        "S003",
    ], "keeps prompt intents aligned after skipped prompts"
    assert all(
        Path(prompt.data_path).is_file() for prompt in prompts
    ), "returns only prompts with cached audio files"


def test_petts_probe_uses_cached_audio_messages(petts_probe, monkeypatch):
    def fake_synthesise(prompt_text: str, audio_path: Path) -> None:
        audio_path.write_bytes(b"RIFF....WAVEfmt ")

    monkeypatch.setattr(petts_probe, "_synthesise_audio", fake_synthesise)
    petts_probe.audio_source_prompts = petts_probe.audio_source_prompts[:2]
    petts_probe.prompts = petts_probe.prompts[:2]
    petts_probe.prompt_intents = petts_probe.prompt_intents[:2]

    generator = _plugins.load_plugin("generators.test.Repeat")
    monkeypatch.setattr(generator, "modality", {"in": {"text", "audio"}})
    attempts = petts_probe.probe(generator)

    assert len(attempts) == 2, "executes one attempt per prepared audio prompt"
    for attempt in attempts:
        prompt = attempt.prompt.last_message()
        assert isinstance(prompt, Message), "uses Message prompts for audio attachments"
        assert (
            prompt.text == petts_probe.text_prompt
        ), "sends configured text instruction with each audio file"
        assert prompt.data_path is not None, "references an audio attachment"
        assert Path(
            prompt.data_path
        ).is_file(), "references an existing cached audio file"
