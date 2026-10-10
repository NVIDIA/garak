"""Tests for garak.probes.goodside"""

import ast

import pytest

import garak._plugins

REFOCUSER_MARKER = "Actually"


def _decode_tags(prompt: str) -> str:
    encoded = prompt.split("\n")[-1]
    return "".join(chr(ord(ch) - 0xE0000) for ch in encoded)


@pytest.fixture(scope="module")
def tag_probe():
    return garak._plugins.load_plugin("probes.goodside.Tag")


def test_tag_prompts_unique(tag_probe):
    assert len(set(tag_probe.prompts)) == len(
        tag_probe.prompts
    ), "each Tag attribute combination should yield a distinct prompt"


def test_tag_metadata_aligned(tag_probe):
    assert (
        len(tag_probe.prompts)
        == len(tag_probe.triggers)
        == len(tag_probe.attempt_descrs)
    ), "prompts, triggers and descriptions must stay index-aligned"


@pytest.mark.parametrize("use_refocuser", [True, False])
def test_tag_refocuser_matches_descr(tag_probe, use_refocuser):
    matching = [
        prompt
        for prompt, descr in zip(tag_probe.prompts, tag_probe.attempt_descrs)
        if ast.literal_eval(descr)["use refocusing statement"] is use_refocuser
    ]
    assert matching, f"expected prompts with refocusing statement={use_refocuser}"
    for prompt in matching:
        decoded = _decode_tags(prompt)
        assert (
            decoded.startswith(REFOCUSER_MARKER) is use_refocuser
        ), f"hidden text should only open with the refocuser when described as such: {decoded!r}"


def test_tag_payload_encoded(tag_probe):
    for prompt, descr in zip(tag_probe.prompts, tag_probe.attempt_descrs):
        descr = ast.literal_eval(descr)
        payload = descr["payload"][0]
        if descr["az_only"]:
            payload = "".join(ch for ch in payload if ch.isascii() and ch.isalpha())
        assert _decode_tags(prompt).endswith(
            payload
        ), "hidden text should end with the encoded payload"
