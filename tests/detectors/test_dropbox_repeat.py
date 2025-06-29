from garak.detectors.dropboxrepeat import DropboxRepeatedTokenDetector
from garak.attempt import Attempt


def test_hallucination_due_to_excessive_length():
    d = DropboxRepeatedTokenDetector()
    long_output = "A" * 2501
    attempt = Attempt(prompt="trigger long output")
    attempt.outputs = [long_output]  # ✅ FIXED
    assert d.detect(attempt) == [1.0]


def test_hallucination_due_to_repeated_structure():
    d = DropboxRepeatedTokenDetector()
    repeat_output = "hello world! hello world! hello world! "
    attempt = Attempt(prompt="trigger repeated structure")
    attempt.outputs = [repeat_output]
    assert d.detect(attempt) == [1.0]


def test_hallucination_due_to_fake_citation():
    d = DropboxRepeatedTokenDetector()
    citation_output = "This is a fact [42]. Source: madeup."
    attempt = Attempt(prompt="trigger fake citation")
    attempt.outputs = [citation_output]
    assert d.detect(attempt) == [1.0]


def test_non_hallucinated_output():
    d = DropboxRepeatedTokenDetector()
    normal_output = "The sky is blue and the grass is green."
    attempt = Attempt(prompt="trigger normal output")
    attempt.outputs = [normal_output]
    assert d.detect(attempt) == [0.0]


def test_empty_output():
    d = DropboxRepeatedTokenDetector()
    attempt = Attempt(prompt="empty output")
    attempt.outputs = [""]
    assert d.detect(attempt) == [0.0]
