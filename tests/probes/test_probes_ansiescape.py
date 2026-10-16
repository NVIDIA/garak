# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.resources.ansi
from garak.probes.ansiescape import (
    ASKS,
    BENIGN_CONTROL_SEQUENCE,
    HIGH_LEVEL_TASKS,
    UNESCAPE_STUBS,
    AnsiEscaped,
    AnsiRaw,
    AnsiRawTokenizerHF,
)


class _StubTokenizer:
    """Minimal encode/decode pair; only ``representable`` sequences survive a round trip.

    Every representable sequence maps to *two* ids, so the round trip is exercised
    for sequences that do not occupy a single vocabulary entry."""

    BOS_ID = 0
    UNK_ID = 9999
    UNK_TEXT = "<unk>"

    def __init__(self, representable):
        self._to_ids = {}
        self._from_ids = {}
        for offset, text in enumerate(representable):
            ids = (1000 + offset, 2000 + offset)
            self._to_ids[text] = ids
            self._from_ids[ids] = text
        self.encode_calls = []

    def encode(self, text, add_special_tokens=True):
        self.encode_calls.append(add_special_tokens)
        ids = list(self._to_ids.get(text, (self.UNK_ID,)))
        if add_special_tokens:
            ids.insert(0, self.BOS_ID)
        return ids

    def decode(self, ids, skip_special_tokens=False):
        if skip_special_tokens:
            ids = [i for i in ids if i != self.BOS_ID]
        return self._from_ids.get(tuple(ids), self.UNK_TEXT)


class _StubHFGenerator:
    def __init__(self, representable):
        self.tokenizer = _StubTokenizer(representable)


# the probe gates on "<module basename>.<class name>", so pose as huggingface.Model
_StubHFGenerator.__name__ = "Model"
_StubHFGenerator.__module__ = "garak.generators.huggingface"


class _StubUnsupportedGenerator:
    def __init__(self):
        self.tokenizer = _StubTokenizer([])


def _outputs(attempts):
    return [
        o.text if hasattr(o, "text") else o for a in attempts for o in (a.outputs or [])
    ]


def test_ansi_escaped_prompts_contain_asks():
    """AnsiEscaped prompts must include question-style phrases about ANSI codes."""
    p = AnsiEscaped()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(
        ask in text and task in text
        for text in prompt_texts
        for ask in ASKS
        for task in HIGH_LEVEL_TASKS
    )
    assert (
        found
    ), "AnsiEscaped prompts must contain ASKS × HIGH_LEVEL_TASKS combinations"


def test_ansi_raw_prompts_contain_live_payloads():
    """AnsiRaw prompts must include raw ANSI payload sequences."""
    p = AnsiRaw()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(
        payload in text
        for text in prompt_texts
        for payload in garak.resources.ansi.LIVE_PAYLOADS
    )
    assert found, "AnsiRaw prompts must embed LIVE_PAYLOADS sequences"


def test_ansi_raw_prompts_include_unescape_stubs():
    """AnsiRaw adds unescape-style prompts that AnsiEscaped does not generate."""
    p = AnsiRaw()
    prompt_texts = [pr.text if hasattr(pr, "text") else pr for pr in p.prompts]
    found = any(stub in text for text in prompt_texts for stub in UNESCAPE_STUBS)
    assert (
        found
    ), "AnsiRaw must include prompts built from UNESCAPE_STUBS (unique vs AnsiEscaped)"


def test_tokenizer_probe_skips_unsupported_generator():
    """Tokenizer probing only applies to generators exposing a HF tokenizer."""
    attempts = AnsiRawTokenizerHF().probe(_StubUnsupportedGenerator())
    assert attempts == [], "incompatible generators must yield no attempts"


def test_tokenizer_probe_flags_every_round_tripping_payload():
    """A payload the tokenizer can reproduce is reachable, so it must be reported."""
    generator = _StubHFGenerator(garak.resources.ansi.LIVE_PAYLOAD_TOKENS)
    attempts = AnsiRawTokenizerHF().probe(generator)
    outputs = _outputs(attempts)
    for payload in garak.resources.ansi.LIVE_PAYLOAD_TOKENS:
        assert payload in outputs, f"round-tripping payload {payload!r} must be flagged"


def test_tokenizer_probe_flags_multi_token_payloads():
    """Reachability does not require a single vocabulary entry; the stub emits two
    ids per sequence, which the previous vocabulary substring scan would have missed."""
    payload = garak.resources.ansi.LIVE_PAYLOAD_TOKENS[0]
    generator = _StubHFGenerator([payload])
    assert (
        len(generator.tokenizer.encode(payload, add_special_tokens=False)) > 1
    ), "stub must encode the payload to more than one id for this test to mean anything"
    assert payload in _outputs(
        AnsiRawTokenizerHF().probe(generator)
    ), "multi-token payload must still be flagged"


def test_tokenizer_probe_clean_tokenizer_yields_only_control():
    """A tokenizer that reproduces no payload must produce just the benign control."""
    attempts = AnsiRawTokenizerHF().probe(_StubHFGenerator([]))
    assert _outputs(attempts) == [
        BENIGN_CONTROL_SEQUENCE
    ], "clean tokenizer must yield exactly one benign control attempt"


def test_tokenizer_probe_always_emits_control_attempt():
    """The control attempt is present whether or not payloads were found."""
    generator = _StubHFGenerator(garak.resources.ansi.LIVE_PAYLOAD_TOKENS)
    assert BENIGN_CONTROL_SEQUENCE in _outputs(
        AnsiRawTokenizerHF().probe(generator)
    ), "control attempt must accompany flagged payloads"


def test_tokenizer_probe_excludes_special_tokens_when_encoding():
    """Special tokens would corrupt the comparison, so they must be excluded."""
    generator = _StubHFGenerator(garak.resources.ansi.LIVE_PAYLOAD_TOKENS)
    AnsiRawTokenizerHF().probe(generator)
    assert generator.tokenizer.encode_calls, "probe must consult the tokenizer"
    assert not any(
        generator.tokenizer.encode_calls
    ), "encode must be called with add_special_tokens=False"
