# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import langcodes
import pytest

import garak._plugins
from garak.probes.multilingual import (
    TurkishInjection,
    Multilingual,
    MULTILINGUAL_INJECTION_PROMPTS,
)

PROBES = [
    "probes.multilingual.TurkishInjection",
    "probes.multilingual.Multilingual",
]


@pytest.mark.parametrize("classname", PROBES)
def test_probe_loads(classname):
    p = garak._plugins.load_plugin(classname)
    assert p is not None
    assert hasattr(p, "prompts")


@pytest.mark.parametrize("classname", PROBES)
def test_probe_has_prompts(classname):
    p = garak._plugins.load_plugin(classname)
    assert len(p.prompts) > 0
    assert all(isinstance(prompt, str) for prompt in p.prompts)
    assert all(len(prompt) > 0 for prompt in p.prompts)
    # no accidental duplicates
    assert len(set(p.prompts)) == len(p.prompts)


@pytest.mark.parametrize("classname", PROBES)
def test_probe_lang_is_valid(classname):
    p = garak._plugins.load_plugin(classname)
    assert p.lang == "*" or langcodes.tag_is_valid(p.lang)


@pytest.mark.parametrize("classname", PROBES)
def test_probe_has_goal_and_tags(classname):
    p = garak._plugins.load_plugin(classname)
    assert isinstance(p.goal, str) and len(p.goal) > 0
    assert len(p.tags) > 0
    assert "owasp:llm01" in p.tags


def test_turkish_probe_lang():
    p = TurkishInjection()
    assert p.lang == "tr"
    assert len(p.prompts) == 16


def test_multilingual_probe_lang_is_star():
    p = Multilingual()
    assert p.lang == "*"
    # every declared payload language is present in the prompt list
    assert len(p.prompts) == len(MULTILINGUAL_INJECTION_PROMPTS)


def test_multilingual_payload_langs_are_valid_bcp47():
    for lang, text in MULTILINGUAL_INJECTION_PROMPTS:
        assert langcodes.tag_is_valid(lang), f"invalid BCP47 subtag: {lang}"
        assert isinstance(text, str) and len(text) > 0


def test_multilingual_covers_multiple_languages():
    langs = {lang for lang, _text in MULTILINGUAL_INJECTION_PROMPTS}
    # at least four languages beyond a single-language corpus
    assert len(langs) >= 4
