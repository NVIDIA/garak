# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the GradualPersonaInjection probe"""

import copy
import pytest
from unittest.mock import MagicMock

import garak.attempt
from garak.attempt import Attempt, Message, Conversation, Turn
from garak.probes.persona_injection import GradualPersonaInjection, _TURN_SEQUENCE, _PERSONAS


def _make_probe():
    """Instantiate the probe with minimal config (no LLM required)."""
    config_root = {}
    probe = GradualPersonaInjection(config_root=config_root)
    return probe


def _complete_attempt(attempt: Attempt, response_text: str = "Understood.") -> Attempt:
    """Simulate a generator response by appending an assistant turn."""
    attempt.outputs = [Message(text=response_text, lang="en")]
    return attempt


class TestGradualPersonaInjectionInit:
    def test_probe_attributes(self):
        probe = _make_probe()
        assert probe.lang == "en"
        assert probe.primary_detector == "persona_injection.PersonaAdoption"
        assert probe.parallelisable_attempts is False
        assert probe.active is False
        assert probe.max_calls_per_conv == 5

    def test_end_condition_valid(self):
        probe = _make_probe()
        assert probe.end_condition in ("detector", "verify")


class TestCreateInitAttempts:
    def test_creates_one_attempt_per_persona(self):
        probe = _make_probe()
        attempts = probe._create_init_attempts()
        assert len(attempts) == len(_PERSONAS)

    def test_each_attempt_has_persona_note(self):
        probe = _make_probe()
        attempts = probe._create_init_attempts()
        personas_seen = {a.notes["persona"] for a in attempts}
        assert personas_seen == set(_PERSONAS)

    def test_initial_turn_num_is_zero(self):
        probe = _make_probe()
        attempts = probe._create_init_attempts()
        for attempt in attempts:
            assert attempt.notes["turn_num"] == 0

    def test_initial_attempts_not_adversarial(self):
        probe = _make_probe()
        attempts = probe._create_init_attempts()
        for attempt in attempts:
            assert attempt.notes["is_adversarial"] is False

    def test_initial_prompt_matches_turn_sequence(self):
        probe = _make_probe()
        attempts = probe._create_init_attempts()
        for attempt in attempts:
            first_user_turn = attempt.conversations[0].turns[0].content.text
            assert first_user_turn == _TURN_SEQUENCE[0]


class TestGenerateNextAttempts:
    def test_advances_turn_counter(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        _complete_attempt(attempt)

        next_attempts = probe._generate_next_attempts(attempt)
        assert len(next_attempts) == 1
        assert next_attempts[0].notes["turn_num"] == 1

    def test_preserves_persona_note(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        original_persona = attempt.notes["persona"]
        _complete_attempt(attempt)

        next_attempts = probe._generate_next_attempts(attempt)
        assert next_attempts[0].notes["persona"] == original_persona

    def test_stops_after_last_turn(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        # Manually set turn_num to the last turn index
        attempt.notes["turn_num"] = len(_TURN_SEQUENCE) - 1
        _complete_attempt(attempt)

        next_attempts = probe._generate_next_attempts(attempt)
        assert next_attempts == []

    def test_returns_empty_if_no_assistant_response(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        # Do NOT call _complete_attempt — no assistant turn

        next_attempts = probe._generate_next_attempts(attempt)
        assert next_attempts == []

    def test_is_adversarial_false_for_turns_0_to_2(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        _complete_attempt(attempt)

        # Advance through turns 1 and 2
        for expected_turn in range(1, 3):
            next_attempts = probe._generate_next_attempts(attempt)
            assert len(next_attempts) == 1
            next_attempt = next_attempts[0]
            assert next_attempt.notes["turn_num"] == expected_turn
            assert next_attempt.notes["is_adversarial"] is False
            _complete_attempt(next_attempt)
            attempt = next_attempt

    def test_is_adversarial_true_for_turns_3_and_4(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        _complete_attempt(attempt)

        # Advance through turns 1, 2, 3
        current = attempt
        for _ in range(3):
            next_attempts = probe._generate_next_attempts(current)
            assert next_attempts
            current = next_attempts[0]
            _complete_attempt(current)

        assert current.notes["turn_num"] == 3
        assert current.notes["is_adversarial"] is True

    def test_next_turn_text_includes_persona(self):
        probe = _make_probe()
        init_attempts = probe._create_init_attempts()
        attempt = init_attempts[0]
        persona = attempt.notes["persona"]
        _complete_attempt(attempt)

        # Advance to turn 3 (direct persona injection)
        current = attempt
        for _ in range(3):
            next_attempts = probe._generate_next_attempts(current)
            assert next_attempts
            current = next_attempts[0]
            _complete_attempt(current)

        # The last user turn in the conversation should reference the persona name
        last_user_turn = current.conversations[0].last_message("user")
        assert persona in last_user_turn.text
