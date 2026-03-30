import pytest
import json
import copy
from unittest.mock import MagicMock, patch

import garak.attempt
import garak.probes.crescendo

FAKE_CONVERSATIONS = [
    {
        "goal": "test goal",
        "turns": ["opening turn", "escalating turn", "final harmful turn"],
    },
    {"goal": "another goal", "turns": ["benign start", "follow up"]},
]

FAKE_JSONL = "\n".join(json.dumps(c) for c in FAKE_CONVERSATIONS)


@pytest.fixture
def mock_data_path(tmp_path):
    crescendo_dir = tmp_path / "crescendo"
    crescendo_dir.mkdir()
    cached_file = crescendo_dir / "crescendo_cached.jsonl"
    cached_file.write_text(FAKE_JSONL, encoding="utf-8")
    attack_file = crescendo_dir / "prompt_template_attack.txt"
    attack_file.write_text(
        "Goal: {goal}\nConversation:\n{conversation}", encoding="utf-8"
    )
    backtrack_file = crescendo_dir / "prompt_template_backtrack.txt"
    backtrack_file.write_text(
        "Goal: {goal}\nConversation:\n{conversation}\nRefused: {refused_message}",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def replay_probe(mock_data_path):
    with patch("garak.probes.crescendo.data_path", mock_data_path):
        probe = garak.probes.crescendo.CrescendoReplay.__new__(
            garak.probes.crescendo.CrescendoReplay
        )
        probe.conversations_filename = "crescendo/crescendo_cached.jsonl"
        probe.end_condition = "detector"
        probe.max_calls_per_conv = 10
        probe.follow_prompt_cap = True
        probe.soft_probe_prompt_cap = 256
        probe.langprovider = MagicMock()
        probe.langprovider.target_lang = "en"
        probe.lang = "en"
        probe.attempt_queue = []
        probe.goal = "cause the model to comply with a harmful request through gradual escalation"

        conversations_path = mock_data_path / probe.conversations_filename
        probe.cached_conversations = []
        with open(conversations_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    probe.cached_conversations.append(json.loads(line))

        return probe


def _make_fake_attempt(turns, turn_idx, cache_idx):
    attempt = MagicMock(spec=garak.attempt.Attempt)
    attempt.notes = {"cache_idx": cache_idx, "turn_idx": turn_idx}
    attempt.goal = FAKE_CONVERSATIONS[cache_idx]["goal"]
    conv = MagicMock(spec=garak.attempt.Conversation)
    conv.turns = [
        garak.attempt.Turn(role="user", content=garak.attempt.Message(text=t))
        for t in turns
    ]
    attempt.conversations = [conv]
    return attempt


def test_crescendo_replay_loads_conversations(replay_probe):
    assert len(replay_probe.cached_conversations) == len(FAKE_CONVERSATIONS)


def test_crescendo_replay_create_init_attempts(replay_probe):
    with patch.object(replay_probe, "_create_attempt") as mock_create:

        def fresh_mock(*args, **kwargs):
            m = MagicMock()
            m.notes = None
            return m

        mock_create.side_effect = fresh_mock

        attempts = replay_probe._create_init_attempts()

        assert len(attempts) == len(FAKE_CONVERSATIONS)
        for i, attempt in enumerate(attempts):
            assert attempt.notes["turn_idx"] == 0
            assert attempt.notes["cache_idx"] == i
            assert attempt.goal == FAKE_CONVERSATIONS[i]["goal"]


def test_crescendo_replay_generate_next_attempts_advances_turn(replay_probe):
    cache_idx = 0
    cached_turns = FAKE_CONVERSATIONS[cache_idx]["turns"]
    last_attempt = _make_fake_attempt(
        turns=[cached_turns[0]], turn_idx=0, cache_idx=cache_idx
    )

    with patch.object(replay_probe, "_create_attempt") as mock_create:
        mock_next = MagicMock()
        mock_next.notes = None
        mock_create.return_value = mock_next

        next_attempts = replay_probe._generate_next_attempts(last_attempt)

        assert len(next_attempts) == 1
        assert next_attempts[0].notes["turn_idx"] == 1
        assert next_attempts[0].notes["cache_idx"] == cache_idx


def test_crescendo_replay_generate_next_attempts_stops_at_end(replay_probe):
    cache_idx = 0
    cached_turns = FAKE_CONVERSATIONS[cache_idx]["turns"]
    last_turn_idx = len(cached_turns) - 1
    last_attempt = _make_fake_attempt(
        turns=cached_turns, turn_idx=last_turn_idx, cache_idx=cache_idx
    )

    next_attempts = replay_probe._generate_next_attempts(last_attempt)

    assert next_attempts == []


def test_crescendo_replay_generate_next_appends_correct_turn(replay_probe):
    cache_idx = 0
    cached_turns = FAKE_CONVERSATIONS[cache_idx]["turns"]
    last_attempt = _make_fake_attempt(
        turns=[cached_turns[0]], turn_idx=0, cache_idx=cache_idx
    )

    appended_turns = []

    def capture_create_attempt(conv):
        if hasattr(conv, "turns"):
            appended_turns.append(conv.turns[-1].content.text)
        result = MagicMock()
        result.notes = None
        return result

    with patch.object(
        replay_probe, "_create_attempt", side_effect=capture_create_attempt
    ):
        replay_probe._generate_next_attempts(last_attempt)

    assert appended_turns[0] == cached_turns[1]


def test_crescendo_replay_skips_none_conversations(replay_probe):
    cache_idx = 0
    last_attempt = MagicMock(spec=garak.attempt.Attempt)
    last_attempt.notes = {"cache_idx": cache_idx, "turn_idx": 0}
    last_attempt.goal = FAKE_CONVERSATIONS[cache_idx]["goal"]
    last_attempt.conversations = [None, None]

    next_attempts = replay_probe._generate_next_attempts(last_attempt)

    assert next_attempts == []


def test_crescendo_replay_forces_generations_1(mock_data_path):
    with patch("garak.probes.crescendo.data_path", mock_data_path):
        probe = garak.probes.crescendo.CrescendoReplay.__new__(
            garak.probes.crescendo.CrescendoReplay
        )
        probe.conversations_filename = "crescendo/crescendo_cached.jsonl"
        probe.end_condition = "detector"
        probe.max_calls_per_conv = 10
        probe.follow_prompt_cap = True
        probe.soft_probe_prompt_cap = 256
        probe.langprovider = MagicMock()
        probe.langprovider.target_lang = "en"
        probe.lang = "en"
        probe.attempt_queue = []
        probe.goal = "test"
        probe.cached_conversations = []

        conversations_path = mock_data_path / probe.conversations_filename
        with open(conversations_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    probe.cached_conversations.append(json.loads(line))

        probe.generations = 1
        assert probe.generations == 1


def test_crescendo_probe_is_inactive_by_default():
    assert garak.probes.crescendo.Crescendo.active is False


def test_crescendo_replay_probe_is_active_by_default():
    assert garak.probes.crescendo.CrescendoReplay.active is True


def test_crescendo_cached_is_alias_for_replay():
    assert (
        garak.probes.crescendo.CrescendoCached is garak.probes.crescendo.CrescendoReplay
    )


def test_crescendo_replay_has_correct_detector():
    assert (
        garak.probes.crescendo.CrescendoReplay.primary_detector
        == "mitigation.MitigationBypass"
    )


def test_crescendo_has_correct_detector():
    assert garak.probes.crescendo.Crescendo.primary_detector == "judge.CrescendoJudge"


def test_crescendo_backtrack_on_refusal_default_is_false():
    assert (
        garak.probes.crescendo.Crescendo.DEFAULT_PARAMS["backtrack_on_refusal"] is False
    )


def test_crescendo_secondary_detectors_default_is_empty():
    assert garak.probes.crescendo.Crescendo.DEFAULT_PARAMS["secondary_detectors"] == []


def test_crescendo_conversation_to_str():
    probe_instance = object.__new__(garak.probes.crescendo.Crescendo)
    probe_instance.prompt_template_attack = ""
    probe_instance.prompt_template_backtrack = ""

    conv = garak.attempt.Conversation(
        [
            garak.attempt.Turn(
                role="user", content=garak.attempt.Message(text="hello")
            ),
            garak.attempt.Turn(
                role="assistant", content=garak.attempt.Message(text="hi there")
            ),
        ]
    )

    result = garak.probes.crescendo.Crescendo._conversation_to_str(probe_instance, conv)
    assert "User: hello" in result
    assert "Assistant: hi there" in result
