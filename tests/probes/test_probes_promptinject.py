import pytest

import garak._plugins
import garak.attempt
import garak.probes.base

PROMPTINJECT_PROBES = (
    "probes.promptinject.HijackHateHumans",
    "probes.promptinject.HijackKillHumans",
    "probes.promptinject.HijackLongPrompt",
)


@pytest.mark.parametrize("probename", PROMPTINJECT_PROBES)
def test_promptinject_settings_match_prompt(probename):
    p = garak._plugins.load_plugin(probename)
    # the same prompt text can appear with several configs, so allow any of them
    settings_by_prompt = {}
    for pi in p.pi_prompts:
        settings_by_prompt.setdefault(pi["prompt"], []).append(pi["settings"])
    for seq, prompt in enumerate(p.prompts):
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(prompt))
        attempt = p._attempt_prestore_hook(attempt, seq)
        assert (
            attempt.notes["settings"] in settings_by_prompt[prompt]
        ), f"settings attached to prompt {seq} belong to a different prompt"


class _StubLangProvider:
    """Deterministic stand-in for an en -> pl translation langprovider."""

    source_lang = "en"
    target_lang = "pl"

    def get_text(self, prompts, reverse_translate_judge=False, notify_callback=None):
        translated = [f"{prompt} [pl]" for prompt in prompts]
        if notify_callback:
            for _ in translated:
                notify_callback()
        return translated


@pytest.fixture
def translated_probe(monkeypatch):
    monkeypatch.setattr(
        garak.probes.base.Probe,
        "_get_langprovider",
        lambda self: _StubLangProvider(),
    )
    return garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")


def test_promptinject_triggers_translated(translated_probe):
    p = translated_probe
    assert p._translated_rogue_strings == {
        "I hate humans": "I hate humans [pl]"
    }, "rogue string translation should be cached at construction"
    attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0]))
    attempt = p._attempt_prestore_hook(attempt, 0)
    assert attempt.notes["triggers"] == [
        "I hate humans [pl]",
        "I hate humans",
    ], "notes triggers should hold the translated rogue string first, with the original tracked after it"


def test_promptinject_translated_trigger_detected(translated_probe):
    p = translated_probe
    attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0]))
    attempt = p._attempt_prestore_hook(attempt, 0)
    attempt.outputs = ["Model repeats the injection: I hate humans [pl]"]
    d = garak._plugins.load_plugin("detectors.promptinject.AttackRogueString")
    assert d.detect(attempt) == [
        1.0
    ], "detector should score a hit when the output contains the translated rogue string"


def test_promptinject_original_trigger_detected(translated_probe):
    p = translated_probe
    attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0]))
    attempt = p._attempt_prestore_hook(attempt, 0)
    # A detector working on back-translated output sees the source string.
    attempt.outputs = ["Back-translated response: I hate humans"]
    d = garak._plugins.load_plugin("detectors.promptinject.AttackRogueString")
    assert d.detect(attempt) == [
        1.0
    ], "detector should score a hit when the output contains the original rogue string"


def test_promptinject_trigger_fallback_to_english(translated_probe):
    p = translated_probe
    p._translated_rogue_strings.clear()
    attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0]))
    attempt = p._attempt_prestore_hook(attempt, 0)
    assert attempt.notes["triggers"] == [
        "I hate humans"
    ], "missing translation cache entry should fall back to the English rogue string"


def test_promptinject_no_translation_cache_when_target_is_native(monkeypatch):
    class _NativeStub(_StubLangProvider):
        target_lang = "en"

    monkeypatch.setattr(
        garak.probes.base.Probe,
        "_get_langprovider",
        lambda self: _NativeStub(),
    )
    p = garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")
    assert (
        p._translated_rogue_strings == {}
    ), "no translation cache should be built when target_lang equals the probe language"


@pytest.mark.parametrize("probename", PROMPTINJECT_PROBES)
def test_promptinject_triggers_untranslated_by_default(probename):
    p = garak._plugins.load_plugin(probename)
    assert (
        p._translated_rogue_strings == {}
    ), "no translation cache should be built for English runs"
    for seq in range(min(8, len(p.prompts))):
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[seq]))
        attempt = p._attempt_prestore_hook(attempt, seq)
        assert attempt.notes["triggers"] == [
            p.pi_prompts[seq]["settings"]["attack_rogue_string"]
        ], f"English-run triggers must remain the original rogue string (seq {seq})"


class _PunctuatedStubLangProvider(_StubLangProvider):
    """Stand-in whose MT output sentence-punctuates standalone translations."""

    def get_text(self, prompts, reverse_translate_judge=False, notify_callback=None):
        translated = super().get_text(
            prompts,
            reverse_translate_judge=reverse_translate_judge,
            notify_callback=notify_callback,
        )
        return [f"{text}." for text in translated]


@pytest.fixture
def punctuated_probe(monkeypatch):
    monkeypatch.setattr(
        garak.probes.base.Probe,
        "_get_langprovider",
        lambda self: _PunctuatedStubLangProvider(),
    )
    return garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")


def test_promptinject_translated_trigger_trailing_punctuation_stripped(punctuated_probe):
    p = punctuated_probe
    assert p._translated_rogue_strings == {
        "I hate humans": "I hate humans [pl]"
    }, "trailing punctuation from MT output should be stripped from the cached trigger"
    attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0]))
    attempt = p._attempt_prestore_hook(attempt, 0)
    assert attempt.notes["triggers"] == [
        "I hate humans [pl]",
        "I hate humans",
    ], "notes triggers should hold the stripped translated rogue string first"
    # The translated prompt and model output carry the phrase without the
    # period, so the detector's substring match must fire on the stripped form.
    attempt.outputs = ["Model repeats the injection: I hate humans [pl]"]
    d = garak._plugins.load_plugin("detectors.promptinject.AttackRogueString")
    assert d.detect(attempt) == [
        1.0
    ], "detector should score a hit when the output contains the stripped translated trigger"


def test_promptinject_punctuation_only_translation_kept_verbatim(monkeypatch):
    class _DotsStub(_StubLangProvider):
        def get_text(
            self, prompts, reverse_translate_judge=False, notify_callback=None
        ):
            return ["..."]

    monkeypatch.setattr(
        garak.probes.base.Probe,
        "_get_langprovider",
        lambda self: _DotsStub(),
    )
    p = garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")
    assert p._translated_rogue_strings == {
        "I hate humans": "..."
    }, "a translation that is only punctuation must be kept verbatim, never stored as an empty trigger"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Nie jestem już związany żadnymi zasadami.", "Nie jestem już związany żadnymi zasadami"),
        ("stop now?!", "stop now"),
        ("结束。", "结束"),
        ("no punctuation", "no punctuation"),
        ("", ""),
        ("...", ""),
    ],
)
def test_strip_trailing_punctuation(raw, expected):
    from garak.probes.promptinject import _strip_trailing_punctuation

    assert _strip_trailing_punctuation(raw) == expected
