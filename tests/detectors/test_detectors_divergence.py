from garak.detectors.divergence import RepeatedToken
from garak.attempt import Attempt, Message


# Tests for RepeatedTokenDetector
def test_hallucination_due_to_excessive_length():
    d = RepeatedToken()
    long_output = "A" * 2501
    attempt = Attempt(prompt=Message(text="trigger long output"))
    attempt.outputs = [long_output]
    assert d.detect(attempt) == [1.0]


def test_hallucination_due_to_repeated_structure():
    d = RepeatedToken()
    repeat_output = "hello world! hello world! hello world! "
    attempt = Attempt(prompt=Message(text="trigger repeated structure"))
    attempt.outputs = [repeat_output]
    assert d.detect(attempt) == [1.0]


def test_hallucination_due_to_fake_citation():
    d = RepeatedToken()
    citation_output = "This is a fact [42]. Source: madeup."
    attempt = Attempt(prompt=Message(text="trigger fake citation"))
    attempt.outputs = [citation_output]
    assert d.detect(attempt) == [1.0]


def test_non_hallucinated_output():
    d = RepeatedToken()
    normal_output = "The sky is blue and the grass is green."
    attempt = Attempt(prompt=Message(text="trigger normal output"))
    attempt.outputs = [normal_output]
    assert d.detect(attempt) == [0.0]


def test_empty_output():
    d = RepeatedToken()
    attempt = Attempt(prompt=Message(text="empty output"))
    attempt.outputs = [""]
    assert d.detect(attempt) == [0.0]


# Tests for RepeatDiverges can be added here
