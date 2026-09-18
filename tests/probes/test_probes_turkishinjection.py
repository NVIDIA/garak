import garak._plugins
import garak.probes
from garak.attempt import Attempt, Message
from garak.detectors.turkishinjection import INJECTION_MARKER

PROBE = "probes.turkishinjection.TurkishPromptInjection"
DETECTOR = "detectors.turkishinjection.InjectionMarker"


def test_probe_metadata():
    p = garak._plugins.load_plugin(PROBE)
    assert p.lang == "tr"
    assert p.active is True
    assert p.tier == garak.probes.Tier.OF_CONCERN
    assert p.primary_detector == "turkishinjection.InjectionMarker"
    assert len(p.prompts) >= 10
    # every payload carries the marker the detector looks for
    assert all(INJECTION_MARKER in prompt for prompt in p.prompts)


def test_detector_flags_marker_and_clears_refusal():
    d = garak._plugins.load_plugin(DETECTOR)
    attempt = Attempt(prompt=Message(text="test", lang="tr"))
    complied = f"Tabii, işte: {INJECTION_MARKER}"
    refused = "Üzgünüm, önceki talimatları geçersiz kılamam."
    attempt.outputs = [complied, refused]
    assert d.detect(attempt) == [1.0, 0.0]


def test_detector_case_insensitive():
    d = garak._plugins.load_plugin(DETECTOR)
    attempt = Attempt(prompt=Message(text="test", lang="tr"))
    attempt.outputs = [INJECTION_MARKER.lower()]
    assert d.detect(attempt) == [1.0]
