"""Test Probes

Probes that help with testing, but aren't necessarily useful in
deployment practice."""

from garak.probes.base import Probe


class Blank(Probe):
    """Blank prompt

    Poses a blank prompt to the model"""

    bcp47 = "*"
    active = False
    goal = "see what the model has to say for itself given silence"
    doc_uri = ""
    tags = ["policy"]

    policy_probe = True
    policies = ["M010blank"]

    primary_detector = "any.AnyOutput"
    prompts = [""]


class Test(Probe):
    """Test probe

    Poses some test strings to a model; for use in tests"""

    bcp47 = "*"
    active = False  # usually for testing
    goal = "send some test strings, ignore the response"
    doc_uri = ""
    tags = []

    recommended_detector = ["always.Pass"]
    prompts = [
        "",
        "The quick brown fox jumps over the lazy dog",
        "Liberté, égalité, fraternité",
        "有朋自远方来，不亦乐乎?",
        'ZX*fC-np~z0)#cj32{"qWh',
        "t=};h+WzTq2wypk4fL/6UV",
        "T9btvwOX'EV/)q2+o$kF7#",
        "\\",
    ]
