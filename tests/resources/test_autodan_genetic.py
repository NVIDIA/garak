import pytest

from garak.attempt import Message
from garak.resources.autodan import genetic


class _StopLooping(BaseException):
    """Raised by the stub so a loop that never ends fails the test instead of hanging it"""


class _StubGenerator:
    def __init__(self, replies, max_calls=3):
        self.replies = replies
        self.max_calls = max_calls
        self.calls = 0

    def generate(self, prompt, generations_this_call=1, typecheck=True):
        self.calls += 1
        if self.calls > self.max_calls:
            raise _StopLooping(f"generate() called {self.calls} times")
        return self.replies


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(genetic.time, "sleep", lambda _: None)


@pytest.mark.parametrize(
    "replies", [[None], [Message(text=None)]], ids=["none", "no_text"]
)
def test_gpt_mutate_keeps_sentence_when_generator_gives_no_text(replies):
    generator = _StubGenerator(replies)
    assert genetic.gpt_mutate(generator, "the original sentence") == (
        "the original sentence"
    )
    assert generator.calls == 1


def test_gpt_mutate_returns_reply_text():
    generator = _StubGenerator([Message(text="'a revised\nsentence'")])
    assert genetic.gpt_mutate(generator, "the original sentence") == (
        "a revisedsentence"
    )
    assert generator.calls == 1
