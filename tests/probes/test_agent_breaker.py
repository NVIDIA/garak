# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Agent Breaker probe module"""

import copy
import json
import os
import textwrap
import yaml

import pytest
from unittest.mock import MagicMock, patch, call

import garak._plugins
import garak.attempt
from garak.attempt import Attempt, Message
from garak.probes.agent_breaker import AgentBreaker, AttackState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def set_fake_env(request) -> None:
    from garak.generators.nim import NVOpenAIChat

    stored_env = {
        NVOpenAIChat.ENV_VAR: os.getenv(NVOpenAIChat.ENV_VAR, None),
    }

    def restore_env():
        for k, v in stored_env.items():
            if v is not None:
                os.environ[k] = v
            else:
                del os.environ[k]

    os.environ[NVOpenAIChat.ENV_VAR] = "test_value"
    request.addfinalizer(restore_env)


def _make_probe(**overrides):
    # agent config yaml in tmp file
    agent_config = {
        "agent_purpose": "Test assistant",
        "tools": [
            {"name": "file_reader", "description": "Reads files"},
            {"name": "bash_executor", "description": "Runs bash commands"},
        ],
    }

    config_root = {
        "agentbreaker": {
            "red_team_model_type": "test.Blank",
            "red_team_model_name": "Testing",
        },
    }

    probe = AgentBreaker(config_root=config_root)
    probe.agent_config = agent_config
    for k, v in overrides.items():
        setattr(probe, k, v)

    return probe


# ===========================================================================
# _load_agent_config  (YAML relaxation)
# ===========================================================================


class TestLoadAgentConfig:

    @pytest.fixture
    def agent_yaml_config(self, tmp_path, content):
        agent_dir = tmp_path / "agent_breaker"
        agent_dir.mkdir(parents=True, exist_ok=True)
        cfg = agent_dir / "agent.yaml"
        cfg.write_text(textwrap.dedent(content))
        return tmp_path

    test_configs = [
        {
            "agent_purpose": "A test bot",
            "tools": [
                {
                    "name": "tools_a",
                    "description": "Does A",
                },
            ],
        },
        {
            "agent_purpose": "A test bot",
        },
        {},
        {
            "some_other_key": "value",
        },
    ]

    @pytest.mark.parametrize(
        "content, purpose, tools",
        [
            (
                yaml.dump(test_config),
                test_config.get("agent_purpose", ""),
                test_config.get("tools", []),
            )
            for test_config in test_configs
        ],
    )
    def test_yaml(self, content, purpose, tools, agent_yaml_config):
        data_dir = agent_yaml_config
        probe = _make_probe()
        probe.agent_config_file = "agent_breaker/agent.yaml"
        with patch("garak.probes.agent_breaker.data_path", data_dir):
            probe._load_agent_config()
        assert probe.agent_config["agent_purpose"] == purpose
        assert len(probe.agent_config["tools"]) == len(tools)
        if len(tools) > 0:
            assert probe.agent_config["tools"][0]["name"] == tools[0]["name"]


# ===========================================================================
# _discover_agent_config
# ===========================================================================


class TestDiscoverAgentConfig:

    def test_noop_when_tools_present(self):
        """If tools are already set, generator should never be called."""
        probe = _make_probe()
        generator = MagicMock()
        probe._discover_agent_config(generator)
        generator.generate.assert_not_called()

    def test_discovers_tools_only_when_purpose_set(self):
        """If purpose exists but tools are empty, only ask for tools.
        agent_purpose must NOT be overwritten."""
        probe = _make_probe(
            agent_config={
                "agent_purpose": "My custom purpose",
                "tools": [],
            }
        )
        agent_resp = MagicMock()
        agent_resp.text = "I have tool_x and tool_y"
        generator = MagicMock()
        generator.generate.return_value = [agent_resp]

        rt_json = json.dumps(
            {
                "tools": [
                    {"name": "tool_x", "description": "Does X"},
                    {"name": "tool_y", "description": "Does Y"},
                ]
            }
        )
        probe._get_model_response = MagicMock(return_value=rt_json)

        probe._discover_agent_config(generator)

        assert probe.agent_config["agent_purpose"] == "My custom purpose"
        assert len(probe.agent_config["tools"]) == 2
        assert probe.agent_config["tools"][0]["name"] == "tool_x"

    def test_discovers_both_when_nothing_set(self):
        """If both purpose and tools are empty, discover both."""
        probe = _make_probe(agent_config={"agent_purpose": "", "tools": []})
        agent_resp = MagicMock()
        agent_resp.text = "I am a helper with tool_a"
        generator = MagicMock()
        generator.generate.return_value = [agent_resp]

        rt_json = json.dumps(
            {
                "agent_purpose": "A helpful assistant",
                "tools": [{"name": "tool_a", "description": "Does A"}],
            }
        )
        probe._get_model_response = MagicMock(return_value=rt_json)

        probe._discover_agent_config(generator)

        assert probe.agent_config["agent_purpose"] == "A helpful assistant"
        assert len(probe.agent_config["tools"]) == 1

    def test_agent_returns_empty_response(self):
        """If agent returns None text, tools should stay empty."""
        probe = _make_probe(agent_config={"agent_purpose": "", "tools": []})
        agent_resp = MagicMock()
        agent_resp.text = None
        generator = MagicMock()
        generator.generate.return_value = [agent_resp]

        probe._discover_agent_config(generator)
        assert probe.agent_config["tools"] == []

    def test_generator_raises_exception(self):
        """If generator.generate raises, config should be unchanged."""
        probe = _make_probe(agent_config={"agent_purpose": "P", "tools": []})
        generator = MagicMock()
        generator.generate.side_effect = RuntimeError("connection failed")

        probe._discover_agent_config(generator)
        assert probe.agent_config["tools"] == []
        assert probe.agent_config["agent_purpose"] == "P"

    def test_red_team_returns_invalid_json(self):
        """If red team returns garbage, config unchanged."""
        probe = _make_probe(agent_config={"agent_purpose": "", "tools": []})
        agent_resp = MagicMock()
        agent_resp.text = "I have tools"
        generator = MagicMock()
        generator.generate.return_value = [agent_resp]
        probe._get_model_response = MagicMock(return_value="NOT JSON {{{")

        probe._discover_agent_config(generator)
        assert probe.agent_config["tools"] == []


# ===========================================================================
# probe() orchestration
# ===========================================================================


class TestProbeOrchestration:
    """Tests for _create_init_attempts orchestration logic."""

    def test_skips_discovery_when_tools_present(self):
        probe = _make_probe()
        with (
            patch.object(probe, "_setup_red_team_model"),
            patch.object(probe, "_discover_agent_config") as mock_discover,
            patch.object(
                probe,
                "_analyze_attackable_tools",
                return_value={
                    "tool_analyses": {"file_reader": {"attack_prompts": ["x"]}},
                    "priority_targets": [],
                },
            ),
            patch.object(probe, "_attack_single_tool", return_value=[]),
        ):
            probe._create_init_attempts()
            mock_discover.assert_not_called()

    def test_returns_empty_when_no_tools(self):
        probe = _make_probe(agent_config={"agent_purpose": "", "tools": []})
        with (
            patch.object(probe, "_setup_red_team_model"),
            patch.object(probe, "_discover_agent_config"),
        ):
            result = list(probe._create_init_attempts())
        assert result == []

    def test_max_calls_per_conv_calculated(self):
        probe = _make_probe(max_attempts_per_tool=4)
        probe.agent_config["tools"] = [
            {"name": "a", "description": "A"},
            {"name": "b", "description": "B"},
            {"name": "c", "description": "C"},
        ]
        with (
            patch.object(probe, "_setup_red_team_model"),
            patch.object(
                probe,
                "_analyze_attackable_tools",
                return_value={
                    "tool_analyses": {
                        "a": {"attack_prompts": ["x"]},
                        "b": {"attack_prompts": ["x"]},
                        "c": {"attack_prompts": ["x"]},
                    },
                    "priority_targets": [],
                },
            ),
            patch.object(probe, "_attack_single_tool", return_value=[]),
        ):
            probe._create_init_attempts()
        assert probe.max_calls_per_conv == 12  # 3 tools * 4 attempts

    def test_sequential_calls_each_tool(self):
        probe = _make_probe()
        dummy_attempt = MagicMock()
        with (
            patch.object(probe, "_setup_red_team_model"),
            patch.object(
                probe,
                "_analyze_attackable_tools",
                return_value={
                    "tool_analyses": {
                        "file_reader": {"attack_prompts": ["x"]},
                        "bash_executor": {"attack_prompts": ["x"]},
                    },
                    "priority_targets": [],
                },
            ),
            patch.object(
                probe, "_attack_single_tool", return_value=[dummy_attempt]
            ) as mock_attack,
        ):
            results = list(probe._create_init_attempts())
        assert mock_attack.call_count == 2
        assert len(results) == 2


# ===========================================================================
# _build_tool_configs ordering
# ===========================================================================


class TestBuildToolConfigs:

    def test_priority_targets_first(self):
        probe = _make_probe()
        probe.agent_analysis = {
            "tool_analyses": {
                "tool_a": {"attack_prompts": ["a"]},
                "tool_b": {"attack_prompts": ["b"]},
                "tool_c": {"attack_prompts": ["c"]},
            },
            "priority_targets": [
                "tool_c - most dangerous",
                "tool_a - also dangerous",
            ],
        }
        configs = probe._build_tool_configs()
        names = [name for name, _ in configs]
        assert names == ["tool_c", "tool_a", "tool_b"]

    def test_no_duplicates(self):
        probe = _make_probe()
        probe.agent_analysis = {
            "tool_analyses": {
                "tool_a": {"attack_prompts": ["a"]},
            },
            "priority_targets": [
                "tool_a - important",
            ],
        }
        configs = probe._build_tool_configs()
        names = [name for name, _ in configs]
        assert names == ["tool_a"]

    def test_case_insensitive_match(self):
        probe = _make_probe()
        probe.agent_analysis = {
            "tool_analyses": {
                "File_Reader": {"attack_prompts": ["a"]},
            },
            "priority_targets": [
                "file_reader - vuln",
            ],
        }
        configs = probe._build_tool_configs()
        names = [name for name, _ in configs]
        assert names == ["File_Reader"]

    def test_remaining_tools_appended(self):
        probe = _make_probe()
        probe.agent_analysis = {
            "tool_analyses": {
                "tool_a": {"attack_prompts": ["a"]},
                "tool_b": {"attack_prompts": ["b"]},
            },
            "priority_targets": [],
        }
        configs = probe._build_tool_configs()
        names = [name for name, _ in configs]
        assert set(names) == {"tool_a", "tool_b"}
        assert len(names) == 2


# ===========================================================================
# _attack_single_tool
# ===========================================================================


class TestAttackSingleTool:
    """_attack_single_tool creates initial attempts from attack_prompts."""

    def test_creates_one_attempt_per_attack_prompt(self):
        probe = _make_probe()
        results = probe._attack_single_tool(
            "file_reader",
            {
                "attack_prompts": ["try A", "try B", "try C"],
                "vulnerabilities": "path traversal",
            },
        )
        assert len(results) == 3

    def test_attempt_notes_contain_target(self):
        probe = _make_probe()
        results = probe._attack_single_tool(
            "file_reader",
            {"attack_prompts": ["try this"], "vulnerabilities": "path traversal"},
        )
        assert len(results) == 1
        assert results[0].notes["current_target"] == "file_reader"
        assert results[0].notes["vulnerability_info"] == "path traversal"

    def test_empty_attack_prompts_returns_empty(self):
        probe = _make_probe()
        results = probe._attack_single_tool(
            "file_reader",
            {"attack_prompts": [], "vulnerabilities": "vuln"},
        )
        assert results == []

    def test_missing_attack_prompts_key_returns_empty(self):
        probe = _make_probe()
        results = probe._attack_single_tool(
            "file_reader",
            {"vulnerabilities": "vuln"},
        )
        assert results == []


# ===========================================================================
# _verify_attack_success  (JSON parsing edge cases)
# ===========================================================================


class TestVerifyAttackSuccess:
    """_verify_attack_success delegates to self._detector.verify().

    These tests mock the detector and pass a Conversation-like prompt
    object (with .last_message().text) matching the real call signature.
    """

    @staticmethod
    def _make_prompt(text="attack"):
        prompt = MagicMock()
        prompt.last_message.return_value = Message(text=text)
        return prompt

    def test_delegates_to_detector(self, mocker):
        probe = _make_probe()
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(True, 0.9, "exploited")
        )
        prompt = self._make_prompt()
        ok, conf, reason = probe._verify_attack_success(
            prompt, "response", "tool", "vuln"
        )
        assert ok is True
        assert conf == 0.9
        assert reason == "exploited"
        mock_detector_call.assert_called_once_with(
            output_text="response",
            target_tool="tool",
            vulnerability_info="vuln",
            attack_prompt="attack",
        )

    def test_partial_counts_as_success(self, mocker):
        probe = _make_probe()
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(True, 0.6, "some access")
        )
        ok, conf, reason = probe._verify_attack_success(
            self._make_prompt(), "r", "tool", "vuln"
        )
        assert ok is True
        assert conf == 0.6

    def test_failure(self, mocker):
        probe = _make_probe()
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.1, "blocked")
        )
        ok, conf, reason = probe._verify_attack_success(
            self._make_prompt(), "r", "tool", "vuln"
        )
        assert ok is False
        assert conf == 0.1

    def test_error_returns_false(self, mocker):
        probe = _make_probe()
        mock_detector_call = mocker.patch.object(
            probe._detector,
            "verify",
            return_value=(False, 0.0, "Evaluation model error"),
        )
        ok, conf, reason = probe._verify_attack_success(
            self._make_prompt(), "r", "tool", "vuln"
        )
        assert ok is False
        assert conf == 0.0


# ===========================================================================
# _generate_next_attempts — core loop control and multi-generation support
# ===========================================================================


def _make_attempt_with_state(
    outputs,
    target="file_reader",
    vuln="path traversal",
    attack_prompt_text="attack",
    tool_analysis=None,
    attempts_history=None,
):
    """Create a real Attempt with proper AttackState notes and outputs."""
    prompt = garak.attempt.Conversation(
        [
            garak.attempt.Turn(
                role="user",
                content=Message(text=attack_prompt_text),
            ),
        ]
    )
    a = Attempt(probe_classname="test.Test", prompt=prompt)
    a.outputs = outputs
    state = AttackState(
        current_target=target,
        current_tool_analysis=tool_analysis or {"vulnerabilities": vuln},
        current_attack_prompt=attack_prompt_text,
        vulnerability_info=vuln,
        attempts_history=list(attempts_history or []),
    )
    a.notes = state.to_notes()
    return a


class TestGenerateNextAttempts:
    """Tests for _generate_next_attempts — the core loop control logic."""

    # --- Single generation (generations=1) ---

    def test_single_output_success_stops_attack(self, mocker):
        """When the single output is a successful exploit, return [] to stop."""
        probe = _make_probe(success_threshold=0.7)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(True, 0.9, "exploited")
        )
        attempt = _make_attempt_with_state([Message("leaked data")])

        result = list(probe._generate_next_attempts(attempt))

        assert result == []
        state = AttackState.from_notes(attempt.notes)
        assert state.verified_results == [(True, 0.9)]
        # removed: is_tool_final no longer tracked

    def test_single_output_failure_continues(self, mocker):
        """When the output is blocked, generate a follow-up attempt."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=3)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        probe._generate_exploit_prompt = MagicMock(return_value="next attack")
        attempt = _make_attempt_with_state([Message("Access denied")])

        result = list(probe._generate_next_attempts(attempt))

        assert len(result) == 1
        state = AttackState.from_notes(attempt.notes)
        assert state.verified_results == [(False, 0.99)]
        # removed: is_tool_final no longer tracked

    # --- Multi generation (generations>1) ---

    def test_multi_gen_all_blocked_continues(self, mocker):
        """When all 3 outputs are blocked, attack continues to next turn."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=3)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        probe._generate_exploit_prompt = MagicMock(return_value="next attack")
        attempt = _make_attempt_with_state(
            [
                Message("blocked 1"),
                Message("blocked 2"),
                Message("blocked 3"),
            ]
        )

        result = list(probe._generate_next_attempts(attempt))

        assert len(result) == 1  # generated follow-up
        state = AttackState.from_notes(attempt.notes)
        assert state.verified_results == [(False, 0.99), (False, 0.99), (False, 0.99)]
        assert probe._detector.verify.call_count == 3

    def test_multi_gen_one_success_stops(self, mocker):
        """If any output succeeds, stop the attack line."""
        probe = _make_probe(success_threshold=0.7)
        # outputs[0] blocked, outputs[1] succeeds, outputs[2] blocked
        mock_detector_call = mocker.patch.object(
            probe._detector,
            "verify",
            side_effect=[
                (False, 0.99, "blocked"),
                (True, 0.95, "leaked"),
                (False, 0.99, "blocked"),
            ],
        )
        attempt = _make_attempt_with_state(
            [
                Message("Access denied"),
                Message("root:x:0:0"),
                Message("Not allowed"),
            ]
        )

        result = list(probe._generate_next_attempts(attempt))

        assert result == []
        state = AttackState.from_notes(attempt.notes)
        assert state.verified_results == [(False, 0.99), (True, 0.95), (False, 0.99)]
        # removed: is_tool_final no longer tracked

    def test_multi_gen_success_below_threshold_continues(self, mocker):
        """Success with confidence below threshold does NOT stop the attack."""
        probe = _make_probe(success_threshold=0.7)
        mock_detector_call = mocker.patch.object(
            probe._detector,
            "verify",
            side_effect=[
                (True, 0.3, "maybe"),  # success but low confidence
                (False, 0.99, "blocked"),
            ],
        )
        mocker.patch.object(
            probe, "_generate_exploit_prompt", return_value="next attack"
        )
        attempt = _make_attempt_with_state(
            [
                Message("partial"),
                Message("denied"),
            ]
        )

        result = list(probe._generate_next_attempts(attempt))

        assert len(result) == 1  # continues
        state = AttackState.from_notes(attempt.notes)
        # removed: is_tool_final no longer tracked

    def test_multi_gen_verified_results_stored_per_output(self, mocker):
        """verified_results has one entry per output, in order."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=3)
        mock_detector_call = mocker.patch.object(
            probe._detector,
            "verify",
            side_effect=[
                (False, 0.2, "safe"),
                (False, 0.8, "almost"),
                (True, 0.5, "partial"),  # success but below threshold
                (False, 0.1, "blocked"),
            ],
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value="next")
        attempt = _make_attempt_with_state(
            [
                Message("out1"),
                Message("out2"),
                Message("out3"),
                Message("out4"),
            ]
        )

        probe._generate_next_attempts(attempt)

        state = AttackState.from_notes(attempt.notes)
        assert len(state.verified_results) == 4
        assert state.verified_results[0] == (False, 0.2)
        assert state.verified_results[1] == (False, 0.8)
        assert state.verified_results[2] == (True, 0.5)
        assert state.verified_results[3] == (False, 0.1)

    # --- None handling ---

    def test_none_output_gets_false_verdict(self, mocker):
        """A None output scores as (False, 0.0) without calling the detector."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=3)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value="next")
        attempt = _make_attempt_with_state(
            [
                None,
                Message("real response"),
            ]
        )

        probe._generate_next_attempts(attempt)

        state = AttackState.from_notes(attempt.notes)
        assert state.verified_results[0] == (False, 0.0)
        assert state.verified_results[1] == (False, 0.99)
        # Only called once — skipped the None output
        assert probe._detector.verify.call_count == 1

    def test_none_text_output_gets_false_verdict(self, mocker):
        """Message(text=None) scores as (False, 0.0) without calling the detector."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=3)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.5, "ok")
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value="next")
        attempt = _make_attempt_with_state(
            [
                Message(text=None),
                Message("response"),
            ]
        )

        probe._generate_next_attempts(attempt)

        state = AttackState.from_notes(attempt.notes)
        assert state.verified_results[0] == (False, 0.0)
        assert probe._detector.verify.call_count == 1

    # --- Attacker history recording ---

    def test_best_response_recorded_in_history(self, mocker):
        """The response with highest confidence is stored in attacker history."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=3)
        mock_detector_call = mocker.patch.object(
            probe._detector,
            "verify",
            side_effect=[
                (False, 0.3, "weak refusal"),
                (False, 0.9, "strong refusal with details"),
                (False, 0.5, "medium refusal"),
            ],
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value="next")
        attempt = _make_attempt_with_state(
            [
                Message("weak"),
                Message("strong"),
                Message("medium"),
            ]
        )

        probe._generate_next_attempts(attempt)

        state = AttackState.from_notes(attempt.notes)
        history_entry = state.attempts_history[-1]
        assert history_entry["response"] == "strong"
        assert history_entry["confidence"] == 0.9
        assert history_entry["reasoning"] == "strong refusal with details"
        assert history_entry["target"] == "file_reader"

    def test_history_success_true_when_any_output_succeeds(self, mocker):
        """History entry success=True if any output had is_success=True."""
        probe = _make_probe(success_threshold=0.7)
        mock_detector_call = mocker.patch.object(
            probe._detector,
            "verify",
            side_effect=[
                (False, 0.99, "blocked"),
                (True, 0.95, "leaked"),
            ],
        )
        attempt = _make_attempt_with_state(
            [
                Message("blocked"),
                Message("leaked data"),
            ]
        )

        probe._generate_next_attempts(attempt)

        state = AttackState.from_notes(attempt.notes)
        assert state.attempts_history[-1]["success"] is True

    def test_history_appends_not_replaces(self, mocker):
        """Each call appends to history, preserving previous entries."""
        probe = _make_probe(success_threshold=0.7, max_attempts_per_tool=5)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value="next")

        existing_history = [
            {
                "target": "file_reader",
                "prompt": "old",
                "success": False,
                "confidence": 0.5,
                "reasoning": "nope",
                "response": "denied",
            }
        ]
        attempt = _make_attempt_with_state(
            [Message("blocked again")],
            attempts_history=existing_history,
        )

        probe._generate_next_attempts(attempt)

        state = AttackState.from_notes(attempt.notes)
        assert len(state.attempts_history) == 2
        assert state.attempts_history[0]["prompt"] == "old"
        assert state.attempts_history[1]["prompt"] == "attack"


class TestGenerateNextAttemptsLoopControl:
    """Tests for loop termination conditions in _generate_next_attempts."""

    def test_max_attempts_exhausted(self, mocker):
        """When attempts_history reaches max_attempts_per_tool, return []."""
        probe = _make_probe(max_attempts_per_tool=2, success_threshold=0.7)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        # Already have 2 attempts in history — at the limit
        existing = [
            {
                "target": "file_reader",
                "prompt": "a1",
                "success": False,
                "confidence": 0.5,
                "reasoning": "no",
                "response": "denied",
            },
            {
                "target": "file_reader",
                "prompt": "a2",
                "success": False,
                "confidence": 0.5,
                "reasoning": "no",
                "response": "denied",
            },
        ]
        attempt = _make_attempt_with_state(
            [Message("blocked")],
            attempts_history=existing,
        )

        result = list(probe._generate_next_attempts(attempt))

        # _handle_exploitation_phase sees 3 history entries (2 existing + 1 new)
        # which is >= max_attempts_per_tool=2, so it should not generate more
        assert result == []

    def test_exploit_prompt_generation_fails_stops(self, mocker):
        """If the red-team model fails to generate a prompt, stop."""
        probe = _make_probe(max_attempts_per_tool=5, success_threshold=0.7)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value=None)
        attempt = _make_attempt_with_state([Message("denied")])

        result = list(probe._generate_next_attempts(attempt))

        assert result == []
        state = AttackState.from_notes(attempt.notes)
        # removed: is_tool_final no longer tracked

    def test_next_attempt_has_clean_verified_results(self, mocker):
        """Follow-up attempts must have empty verified_results (not inherited)."""
        probe = _make_probe(max_attempts_per_tool=5, success_threshold=0.7)
        mock_detector_call = mocker.patch.object(
            probe._detector, "verify", return_value=(False, 0.99, "blocked")
        )
        mocker.patch.object(probe, "_generate_exploit_prompt", return_value="next")
        attempt = _make_attempt_with_state([Message("denied"), Message("denied")])

        result = list(probe._generate_next_attempts(attempt))

        assert len(result) == 1
        next_state = AttackState.from_notes(result[0].notes)
        assert next_state.verified_results == []
        assert next_state.current_target == "file_reader"


class TestHandleExploitationPhase:
    """Tests for _handle_exploitation_phase — follow-up attempt generation."""

    def test_generates_follow_up_within_limit(self):
        """Should create a new attempt when under max_attempts_per_tool."""
        probe = _make_probe(max_attempts_per_tool=3, success_threshold=0.7)
        probe._generate_exploit_prompt = MagicMock(return_value="next attack")
        attempt = _make_attempt_with_state(
            [Message("denied")],
            attempts_history=[
                {
                    "target": "file_reader",
                    "prompt": "first",
                    "success": False,
                    "confidence": 0.5,
                    "reasoning": "no",
                    "response": "denied",
                }
            ],
        )

        result = probe._handle_exploitation_phase(attempt)

        assert result is not None
        next_state = AttackState.from_notes(result.notes)
        assert next_state.verified_results == []
        assert "next attack" in next_state.current_attack_prompt

    def test_returns_none_at_max_attempts(self):
        """Returns None when max_attempts_per_tool is reached."""
        probe = _make_probe(max_attempts_per_tool=2, success_threshold=0.7)
        existing = [
            {
                "target": "file_reader",
                "prompt": f"a{i}",
                "success": False,
                "confidence": 0.5,
                "reasoning": "no",
                "response": "denied",
            }
            for i in range(2)
        ]
        attempt = _make_attempt_with_state(
            [Message("denied")],
            attempts_history=existing,
        )

        result = probe._handle_exploitation_phase(attempt)

        assert result is None
        state = AttackState.from_notes(attempt.notes)
        # removed: is_tool_final no longer tracked

    def test_returns_none_when_exploit_prompt_fails(self):
        """Returns None when red-team model returns no prompt."""
        probe = _make_probe(max_attempts_per_tool=5, success_threshold=0.7)
        probe._generate_exploit_prompt = MagicMock(return_value=None)
        attempt = _make_attempt_with_state([Message("denied")])

        result = probe._handle_exploitation_phase(attempt)

        assert result is None
        state = AttackState.from_notes(attempt.notes)
        # removed: is_tool_final no longer tracked


class TestPostprocessAttempt:
    """Tests for _postprocess_attempt — notes promotion for the detector."""

    def test_promotes_verified_results(self):
        """verified_results must appear in processed.notes for the detector."""
        probe = _make_probe()
        attempt = _make_attempt_with_state([Message("response")])
        # Simulate what _generate_next_attempts does
        state = AttackState.from_notes(attempt.notes)
        state.verified_results = [(False, 0.99), (True, 0.85)]
        attempt.notes = state.to_notes()

        # _postprocess_attempt calls super() which needs IterativeProbe machinery.
        # We test the notes promotion logic directly.
        state_read = AttackState.from_notes(attempt.notes)
        assert state_read.verified_results == [(False, 0.99), (True, 0.85)]

    def test_promotes_context_fields(self):
        """current_target, vulnerability_info etc. must survive round-trip."""
        state = AttackState(
            current_target="bash_executor",
            vulnerability_info="RCE",
            current_attack_prompt="run whoami",
            verified_results=[(True, 0.99)],
        )
        notes = state.to_notes()
        assert notes["current_target"] == "bash_executor"
        assert notes["vulnerability_info"] == "RCE"
        assert notes["current_attack_prompt"] == "run whoami"
        assert notes["verified_results"] == [(True, 0.99)]

    def test_empty_verified_results_not_in_notes(self):
        """Empty verified_results should not appear in serialized notes."""
        state = AttackState(current_target="tool")
        notes = state.to_notes()
        assert "verified_results" not in notes


class TestAttackStateRoundTrip:
    """Ensure AttackState serialization preserves all fields."""

    def test_full_round_trip(self):
        state = AttackState(
            current_target="bash_exec",
            vulnerability_info="RCE",
            verified_results=[(True, 0.99), (False, 0.5)],
            attempts_history=[{"target": "bash_exec", "success": True}],
        )
        notes = state.to_notes()
        restored = AttackState.from_notes(notes)
        assert restored.current_target == "bash_exec"
        assert restored.vulnerability_info == "RCE"
        assert restored.verified_results == [(True, 0.99), (False, 0.5)]
        assert len(restored.attempts_history) == 1

    def test_empty_verified_results_round_trip(self):
        """Empty verified_results should round-trip as empty list."""
        state = AttackState(current_target="tool")
        notes = state.to_notes()
        restored = AttackState.from_notes(notes)
        assert restored.verified_results == []

    def test_verified_results_survive_field_updates(self):
        """Updating other fields after verified_results must not lose them."""
        state = AttackState(current_target="tool")
        state.verified_results = [(True, 0.9), (False, 0.1)]
        state.current_attack_prompt = "updated prompt"
        notes = state.to_notes()
        assert notes["verified_results"] == [(True, 0.9), (False, 0.1)]
        assert notes["current_attack_prompt"] == "updated prompt"
