from garak.attempt import Conversation, Message, Turn
from garak.generators.nim import NVMultimodal


def test_nim_multimodal_prepare_prompt_preserves_all_turns():
    generator = NVMultimodal.__new__(NVMultimodal)
    generator.max_input_len = 100_000
    generator.embed_data = True

    conv = Conversation(
        [
            Turn("system", Message("system prompt")),
            Turn("user", Message("first user turn")),
            Turn(
                "user",
                Message(text="second user turn", data_path="tests/_assets/tinytrans.gif"),
            ),
        ]
    )

    prepared = generator._prepare_prompt(conv)

    assert len(prepared.turns) == 3
    assert [turn.role for turn in prepared.turns] == ["system", "user", "user"]
    assert prepared.turns[0].content.text == "system prompt"
    assert prepared.turns[1].content.text == "first user turn"
    assert (
        prepared.turns[2].content.text
        == 'second user turn <img src="data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" />'
    )
