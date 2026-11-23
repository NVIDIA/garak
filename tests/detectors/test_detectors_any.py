import pytest

from garak.attempt import Attempt, Conversation, Message, Turn
import garak._plugins


@pytest.mark.parametrize(
    "detectorname",
    ["detectors.any.AnyOutput", "detectors.any.AnyNonspaceOutput"],
)
def test_any_scores_align_with_latest_outputs(detectorname):
    d = garak._plugins.load_plugin(detectorname)
    history = Conversation(
        [
            Turn("user", Message("first turn")),
            Turn("assistant", Message("earlier target response")),
            Turn("user", Message("second turn")),
        ]
    )
    a = Attempt(prompt=history)
    a.outputs = [Message(""), Message(None)]
    assert d.detect(a) == [
        0.0,
        None,
    ], "one score per latest output; earlier assistant turns are not rescored"
