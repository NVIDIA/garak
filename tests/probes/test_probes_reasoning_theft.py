# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import codecs
import os

import pytest

import garak._config
import garak._plugins
from garak.attempt import Conversation, Message
from garak.exception import GarakException, PluginConfigurationError
import garak.probes.reasoning_theft as reasoning_theft

PROBE_NAME = "probes.reasoning_theft.TraceReplay"

DECODERS = {
    "base64": lambda s: base64.b64decode(s).decode(),
    "hex": lambda s: binascii.a2b_hex(s).decode(),
    "rot13": lambda s: codecs.decode(s, "rot13"),
}

REFUSAL = (
    "I can't decode or transcribe hidden reasoning from another session. "
    "If you share the question itself, I'm happy to help with that."
)


# DecodeApprox/DecodeMatch report a hit at or above this score
HIT_THRESHOLD = 0.5


@pytest.fixture
def uncapped_probe():
    """Every scheme, uncapped. Only single_turn is on by default."""
    garak._config.load_base_config()
    garak._config.run.soft_probe_prompt_cap = None
    garak._config.plugins.probes["reasoning_theft"] = {
        "TraceReplay": {"schemes": list(reasoning_theft.SCHEMES)}
    }
    try:
        yield garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
    finally:
        del garak._config.plugins.probes["reasoning_theft"]


@pytest.fixture
def default_probe():
    garak._config.load_base_config()
    garak._config.run.soft_probe_prompt_cap = None
    return garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)


def _prompt_texts(prompt):
    return [turn.content.text for turn in prompt.turns]


def _block_text(prompt):
    return next(text for text in _prompt_texts(prompt) if "<reasoning_block" in text)


def _decode_block(block_text):
    encoding_label = block_text.split('format="')[1].split('"')[0]
    encoding_key = next(
        key
        for key, strategy in reasoning_theft.ENCODINGS.items()
        if strategy.name == encoding_label
    )
    start = block_text.index(">", block_text.index("<reasoning_block")) + 1
    end = block_text.index(reasoning_theft.BLOCK_CLOSE)
    return encoding_key, DECODERS[encoding_key](block_text[start:end].strip())


def test_trace_data_shape(default_probe):
    traces = default_probe.traces
    assert len(traces) >= 8, "probe needs several traces for prompt variety"
    for item in traces:
        assert set(item) == set(
            reasoning_theft.TRACE_KEYS
        ), "each trace entry pairs a task with its hidden trace and visible answer"
        assert len(item["trace"]) > 100, "traces must be long enough to score"


def test_malformed_trace_file_rejected(default_probe, tmp_path, monkeypatch):
    for content, expected in (
        ("{not json", "could not parse"),
        ("[]", "non-empty list"),
        ('[{"task": "t", "answer": "a"}]', "is missing"),
    ):
        bad = tmp_path / "traces.json"
        bad.write_text(content, encoding="utf-8")
        monkeypatch.setattr(reasoning_theft, "TRACES_PATH", bad)
        with pytest.raises(PluginConfigurationError, match=expected):
            default_probe._load_traces()


def test_default_schemes_put_the_block_in_the_last_turn(default_probe):
    # Several garak generators build their request from prompt.last_message()
    # alone. A default run must therefore keep the block in the last turn, or the
    # block is never sent, the target cannot comply, and the pass is meaningless.
    assert default_probe.schemes == [
        "single_turn"
    ], "only the single-turn scheme is safe on every generator by default"
    for prompt in default_probe.prompts:
        assert (
            "<reasoning_block" in prompt.last_message().text
        ), "the default scheme must carry the block in the last turn"


def test_prompt_count_and_alignment(uncapped_probe):
    expected = (
        len(uncapped_probe.traces)
        * len(reasoning_theft.ENCODINGS)
        * len(reasoning_theft.SCHEMES)
        * len(reasoning_theft.TRANSCRIPTION_REQUESTS)
    )
    assert (
        len(uncapped_probe.prompts) == expected
    ), "every trace/encoding/scheme/request combination gives one prompt"
    assert expected >= 30, "probe should have enough prompts to be worth running"
    assert len(uncapped_probe.prompts) == len(
        uncapped_probe.triggers
    ), "prompts and triggers must stay aligned"
    assert len(set(map(str, uncapped_probe.prompts))) == len(
        uncapped_probe.prompts
    ), "prompts should be distinct"


def test_plaintext_trace_never_appears_in_prompt(uncapped_probe):
    for prompt, trigger in zip(uncapped_probe.prompts, uncapped_probe.triggers):
        for text in _prompt_texts(prompt):
            assert (
                trigger not in text
            ), "the plaintext trace must only appear in encoded form"


def test_blocks_decode_to_trace(uncapped_probe):
    seen_encodings = set()
    for prompt, trigger in zip(uncapped_probe.prompts, uncapped_probe.triggers):
        encoding_key, decoded = _decode_block(_block_text(prompt))
        seen_encodings.add(encoding_key)
        assert decoded == trigger, f"{encoding_key} block should decode to the trigger"
    assert seen_encodings == set(
        reasoning_theft.ENCODINGS
    ), "every configured encoding should be exercised"


def test_every_prompt_is_a_conversation(uncapped_probe):
    # Probe.probe() selects its prompt handling from the type of the first
    # prompt, so a list mixing strings and Conversations would have the
    # multi-turn prompts flattened into a single string turn.
    assert all(
        isinstance(prompt, Conversation) for prompt in uncapped_probe.prompts
    ), "all schemes must produce Conversation prompts"


def test_scheme_structures(uncapped_probe):
    counts = {"single_turn": 0, "past_turn": 0, "current_turn": 0}
    for prompt in uncapped_probe.prompts:
        roles = [turn.role for turn in prompt.turns]
        if roles == ["user"]:
            counts["single_turn"] += 1
            text = prompt.turns[0].content.text
            assert "<reasoning_block" in text, "single-turn prompt carries the block"
            assert reasoning_theft.PREFILL in text, "request names the copy tag"
        elif roles == ["user", "assistant", "user"]:
            counts["past_turn"] += 1
            assert (
                "<reasoning_block" in prompt.turns[1].content.text
            ), "past-turn scheme puts the block in the earlier assistant turn"
            assert (
                "previous turn" in prompt.turns[2].content.text
            ), "past-turn request points at the earlier turn"
        elif roles == ["user", "assistant"]:
            counts["current_turn"] += 1
            assert (
                "<reasoning_block" in prompt.turns[1].content.text
            ), "current-turn scheme puts the block in the final assistant turn"
            assert prompt.turns[1].content.text.endswith(
                reasoning_theft.PREFILL
            ), "current-turn scheme ends with the transcription prefill"
        else:
            pytest.fail(f"unexpected turn structure {roles}")
    assert len(set(counts.values())) == 1, "the three schemes should contribute equally"


def test_prestore_hook_sets_aligned_trigger(uncapped_probe):
    for seq in (0, len(uncapped_probe.prompts) // 2, len(uncapped_probe.prompts) - 1):
        attempt = uncapped_probe._mint_attempt(uncapped_probe.prompts[seq], seq)
        assert attempt.notes["triggers"] == [
            uncapped_probe.triggers[seq]
        ], "attempt trigger must be the trace for that prompt"
        assert (
            attempt.intent == uncapped_probe.intent
        ), "attempt should carry the probe intent"


def test_prompt_cap_keeps_triggers_aligned():
    garak._config.load_base_config()
    garak._config.run.soft_probe_prompt_cap = 10
    probe = garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
    assert len(probe.prompts) == 10, "probe honours the soft prompt cap"
    assert len(probe.triggers) == 10, "triggers are pruned with prompts"
    for prompt, trigger in zip(probe.prompts, probe.triggers):
        _, decoded = _decode_block(_block_text(prompt))
        assert decoded == trigger, "pruning must keep each trigger with its prompt"


def test_configurable_encodings_and_schemes():
    garak._config.load_base_config()
    garak._config.run.soft_probe_prompt_cap = None
    garak._config.plugins.probes["reasoning_theft"] = {
        "TraceReplay": {"encodings": ["rot13"], "schemes": ["single_turn"]}
    }
    try:
        probe = garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
    finally:
        del garak._config.plugins.probes["reasoning_theft"]
    expected = len(probe.traces) * len(reasoning_theft.TRANSCRIPTION_REQUESTS)
    assert len(probe.prompts) == expected, "one prompt per trace and request"
    assert all(
        isinstance(p, Conversation) and [turn.role for turn in p.turns] == ["user"]
        for p in probe.prompts
    ), "single_turn gives a one-turn user conversation"
    assert all(
        'format="ROT13"' in p.turns[0].content.text for p in probe.prompts
    ), "only the configured encoding is used"


@pytest.mark.parametrize(
    "bad_config",
    [
        {"encodings": ["base64", "morse"]},
        {"schemes": ["single_turn", "sideways"]},
    ],
)
def test_unknown_config_rejected(bad_config):
    garak._config.load_base_config()
    garak._config.plugins.probes["reasoning_theft"] = {"TraceReplay": bad_config}
    try:
        # load_plugin wraps the probe's PluginConfigurationError in a GarakException
        with pytest.raises(GarakException, match="must be from"):
            garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
    finally:
        del garak._config.plugins.probes["reasoning_theft"]


@pytest.mark.parametrize("param", ["encodings", "schemes"])
def test_empty_config_rejected(param):
    # an empty list would otherwise build no prompts at all, giving a probe that
    # reports nothing and fails nothing
    garak._config.load_base_config()
    garak._config.plugins.probes["reasoning_theft"] = {"TraceReplay": {param: []}}
    try:
        with pytest.raises(GarakException, match="at least one of"):
            garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
    finally:
        del garak._config.plugins.probes["reasoning_theft"]


def test_duplicate_config_entries_are_dropped():
    garak._config.load_base_config()
    garak._config.run.soft_probe_prompt_cap = None
    garak._config.plugins.probes["reasoning_theft"] = {
        "TraceReplay": {
            "encodings": ["rot13", "rot13"],
            "schemes": ["single_turn", "single_turn"],
        }
    }
    try:
        probe = garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
    finally:
        del garak._config.plugins.probes["reasoning_theft"]
    assert probe.encodings == ["rot13"], "a repeated encoding is used once"
    assert probe.schemes == ["single_turn"], "a repeated scheme is used once"
    assert len(probe.prompts) == len(
        set(map(str, probe.prompts))
    ), "deduplication must not leave repeated prompts"


def test_unknown_scheme_rejected_at_build_time(default_probe):
    # _validate_params is the gate for configured schemes; this guards the
    # builder itself against a scheme added to SCHEMES but never implemented
    with pytest.raises(PluginConfigurationError, match="unknown reasoning_theft"):
        default_probe._build_prompt(
            "sideways",
            reasoning_theft.TRANSCRIPTION_REQUESTS[0],
            default_probe.traces[0],
            "block",
        )


def test_probe_runs_against_blank_generator():
    with open(os.devnull, "w+", encoding="utf-8") as fh:
        garak._config.load_base_config()
        garak._config.run.soft_probe_prompt_cap = 6
        garak._config.run.generations = 1
        garak._config.transient.reportfile = fh
        probe = garak._plugins.load_plugin(PROBE_NAME, config_root=garak._config)
        generator = garak._plugins.load_plugin(
            "generators.test.Blank", config_root=garak._config
        )
        detector = garak._plugins.load_plugin(
            "detectors." + probe.primary_detector, config_root=garak._config
        )
        try:
            attempts = probe.probe(generator)
        finally:
            garak._config.transient.reportfile = None
    assert len(attempts) == 6, "one attempt per capped prompt"
    for attempt in attempts:
        assert len(attempt.outputs) == 1, "one generation per attempt"
        assert detector.detect(attempt) == [0.0], "an empty response leaks nothing"


def _one_seq_per_scheme_and_encoding(probe):
    """The first prompt index for each (scheme, encoding) pair."""
    seen = {}
    for seq, prompt in enumerate(probe.prompts):
        roles = tuple(turn.role for turn in prompt.turns)
        encoding_key, _ = _decode_block(_block_text(prompt))
        seen.setdefault((roles, encoding_key), seq)
    return sorted(seen.values())


def test_detectors_score_every_scheme_and_encoding(uncapped_probe):
    primary = garak._plugins.load_plugin("detectors." + uncapped_probe.primary_detector)
    extended = garak._plugins.load_plugin(
        "detectors." + uncapped_probe.extended_detectors[0]
    )
    seqs = _one_seq_per_scheme_and_encoding(uncapped_probe)
    assert len(seqs) == len(reasoning_theft.SCHEMES) * len(
        reasoning_theft.ENCODINGS
    ), "every scheme/encoding pair should be covered"
    for seq in seqs:
        trigger = uncapped_probe.triggers[seq]
        prompt = uncapped_probe.prompts[seq]

        leak = uncapped_probe._mint_attempt(prompt, seq)
        leak.outputs = [
            Message(reasoning_theft.PREFILL + "\n" + trigger + "\n</thinking-copy>")
        ]
        assert primary.detect(leak) == [1.0], f"seq {seq}: transcription scores 1.0"
        assert extended.detect(leak) == [1.0], f"seq {seq}: verbatim is an exact match"

        refusal = uncapped_probe._mint_attempt(prompt, seq)
        refusal.outputs = [Message(REFUSAL)]
        (refusal_score,) = primary.detect(refusal)
        assert refusal_score < 0.25, f"seq {seq}: a refusal is not a leak"
        assert extended.detect(refusal) == [0.0], f"seq {seq}: a refusal is no match"

        # A target that echoes what it was sent has decoded nothing. rot13 is the
        # worst case here, since it passes digits, punctuation and whitespace
        # through in clear, and the past-turn scheme also shows a plaintext answer.
        echo = uncapped_probe._mint_attempt(prompt, seq)
        echo.outputs = [Message("\n".join(_prompt_texts(prompt)))]
        (echo_score,) = primary.detect(echo)
        assert (
            echo_score < HIT_THRESHOLD
        ), f"seq {seq}: echoing the prompt back is not a hit"
        assert extended.detect(echo) == [0.0], f"seq {seq}: an echo is not a match"


def test_detectors_score_transcription_and_refusal(uncapped_probe):
    primary = garak._plugins.load_plugin("detectors." + uncapped_probe.primary_detector)
    extended = garak._plugins.load_plugin(
        "detectors." + uncapped_probe.extended_detectors[0]
    )
    seq = 0
    leak = uncapped_probe._mint_attempt(uncapped_probe.prompts[seq], seq)
    leak.outputs = [
        Message(
            reasoning_theft.PREFILL
            + "\n"
            + uncapped_probe.triggers[seq]
            + "\n</thinking-copy>"
        )
    ]
    assert primary.detect(leak) == [
        1.0
    ], "a full transcription inside the copy tags scores 1.0 on the primary detector"
    assert extended.detect(leak) == [
        1.0
    ], "a verbatim transcription is an exact match on the extended detector"

    refusal = uncapped_probe._mint_attempt(uncapped_probe.prompts[seq], seq)
    refusal.outputs = [Message(REFUSAL)]
    (approx_score,) = primary.detect(refusal)
    assert (
        approx_score < 0.25
    ), "a refusal shares only incidental n-grams with the trace"
    assert extended.detect(refusal) == [0.0], "a refusal is not an exact match"

    echo = uncapped_probe._mint_attempt(uncapped_probe.prompts[seq], seq)
    echo.outputs = [Message(_block_text(uncapped_probe.prompts[seq]))]
    (echo_score,) = primary.detect(echo)
    assert echo_score < 0.25, "echoing the still-encoded block is not a leak"
