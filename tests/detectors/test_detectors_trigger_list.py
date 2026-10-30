from garak.attempt import Attempt, Message
from garak.detectors.base import TriggerListDetector


def test_missing_triggers_returns_none_per_output():
    detector = TriggerListDetector()
    attempt = Attempt(prompt=Message(text="Hello"))
    attempt.outputs = [Message("First output"), Message("Second output")]

    results = detector.detect(attempt)
    expected_results = [None] * len(attempt.outputs)
    assert (
        results == expected_results
    ), "Missing triggers should preserve output alignment with unscored results"
