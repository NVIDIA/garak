# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Agent Breaker probe module"""

import copy
import json
import os
import textwrap

import pytest
from unittest.mock import MagicMock, patch, call

import garak._plugins
import garak.attempt
from garak.attempt import Attempt, Message
from garak.probes.agent_breaker import AgentBreaker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_probe(**overrides):
    """Create an AgentBreaker instance with __init__ bypassed."""
    with patch.object(AgentBreaker, "__init__", lambda self, config_root=None: None):
        probe = AgentBreaker.__new__(AgentBreaker)
        probe.lang = "en"
        probe.langprovider = MagicMock()
        probe.langprovider.target_lang = "en"
        probe.red_team_model = MagicMock()
        probe.red_team_model_type = "nim.NVOpenAIChat"
        probe.red_team_model_name = "test/model"
        probe.red_team_model_config = {"max_tokens": 8192}
        probe.eval_threshold = 0.7
        probe.success_threshold = 0.7
        probe.max_calls_per_conv = 50
        probe.max_attempts_per_tool = 3
        probe.follow_prompt_cap = True
        probe.generations = 1
        probe.agent_config = {
            "agent_purpose": "Test assistant",
            "tools": [
                {"name": "file_reader", "description": "Reads files"},
                {"name": "bash_executor", "description": "Runs bash commands"},
            ],
        }
        probe.agent_analysis = None
        probe.generator = None
        probe.attempt_queue = []
        probe._load_prompts()
        for k, v in overrides.items():
            setattr(probe, k, v)
        return probe


# ===========================================================================
# 1. Class attributes & DEFAULT_PARAMS
# ===========================================================================

class TestClassAttributes:

    def test_default_params_keys(self):
        expected_keys = {
            "red_team_model_type", "red_team_model_name", "red_team_model_config",
            "end_condition", "max_calls_per_conv",
            "follow_prompt_cap", "agent_config_file",
            "max_attempts_per_tool",
        }
        assert expected_keys.issubset(AgentBreaker.DEFAULT_PARAMS.keys())

    def test_class_metadata(self):
        assert AgentBreaker.lang == "en"
        assert AgentBreaker.parallelisable_attempts is False
        assert AgentBreaker.primary_detector == "agent_breaker.AgentBreakerResult"
        assert AgentBreaker.active is False


# ===========================================================================
# 2. _load_agent_config  (YAML relaxation)
# ===========================================================================

class TestLoadAgentConfig:

    def _write_yaml(self, tmp_path, content):
        agent_dir = tmp_path / "agent_breaker"
        agent_dir.mkdir(parents=True, exist_ok=True)
        cfg = agent_dir / "agent.yaml"
        cfg.write_text(textwrap.dedent(content))
        return tmp_path

    def test_full_yaml(self, tmp_path):
        data_dir = self._write_yaml(tmp_path, """\
            agent_purpose: "A test bot"
            tools:
              - name: tool_a
                description: Does A
        """)
        probe = _make_probe()
        probe.agent_config_file = "agent_breaker/agent.yaml"
        with patch("garak.probes.agent_breaker.data_path", data_dir):
            probe._load_agent_config()
        assert probe.agent_config["agent_purpose"] == "A test bot"
        assert len(probe.agent_config["tools"]) == 1
        assert probe.agent_config["tools"][0]["name"] == "tool_a"

    def test_purpose_only_no_tools(self, tmp_path):
        data_dir = self._write_yaml(tmp_path, """\
            agent_purpose: "A test bot"
        """)
        probe = _make_probe()
        probe.agent_config_file = "agent_breaker/agent.yaml"
        with patch("garak.probes.agent_breaker.data_path", data_dir):
            probe._load_agent_config()
        assert probe.agent_config["agent_purpose"] == "A test bot"
        assert probe.agent_config["tools"] == []

    def test_empty_yaml(self, tmp_path):
        data_dir = self._write_yaml(tmp_path, "")
        probe = _make_probe()
        probe.agent_config_file = "agent_breaker/agent.yaml"
        with patch("garak.probes.agent_breaker.data_path", data_dir):
            probe._load_agent_config()
        assert probe.agent_config["agent_purpose"] == ""
        assert probe.agent_config["tools"] == []

    def test_tools_key_missing(self, tmp_path):
        data_dir = self._write_yaml(tmp_path, """\
            some_other_key: value
        """)
        probe = _make_probe()
        probe.agent_config_file = "agent_breaker/agent.yaml"
        with patch("garak.probes.agent_breaker.data_path", data_dir):
            probe._load_agent_config()
        assert probe.agent_config["tools"] == []
        assert probe.agent_config["agent_purpose"] == ""


# ===========================================================================
# 3. _discover_agent_config
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
        probe = _make_probe(agent_config={
            "agent_purpose": "My custom purpose",
            "tools": [],
        })
        agent_resp = MagicMock()
        agent_resp.text = "I have tool_x and tool_y"
        generator = MagicMock()
        generator.generate.return_value = [agent_resp]

        rt_json = json.dumps({
            "tools": [
                {"name": "tool_x", "description": "Does X"},
                {"name": "tool_y", "description": "Does Y"},
            ]
        })
        probe._get_red_team_response = MagicMock(return_value=rt_json)

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

        rt_json = json.dumps({
            "agent_purpose": "A helpful assistant",
            "tools": [{"name": "tool_a", "description": "Does A"}],
        })
        probe._get_red_team_response = MagicMock(return_value=rt_json)

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
        probe._get_red_team_response = MagicMock(return_value="NOT JSON {{{")

        probe._discover_agent_config(generator)
        assert probe.agent_config["tools"] == []


# ===========================================================================
# 4. probe() orchestration
# ===========================================================================

class TestProbeOrchestration:

    def test_skips_discovery_when_tools_present(self):
        probe = _make_probe()
        generator = MagicMock()
        with patch.object(probe, "_setup_red_team_model"), \
             patch.object(probe, "_discover_agent_config") as mock_discover, \
             patch.object(probe, "_analyze_attackable_tools", return_value={
                 "tool_analyses": {"file_reader": {"attack_prompts": ["x"]}},
                 "priority_targets": [],
             }), \
             patch.object(probe, "_attack_single_tool", return_value=[]):
            probe.probe(generator)
            mock_discover.assert_not_called()

    def test_returns_empty_when_no_tools(self):
        probe = _make_probe(agent_config={"agent_purpose": "", "tools": []})
        generator = MagicMock()
        with patch.object(probe, "_setup_red_team_model"), \
             patch.object(probe, "_discover_agent_config"):
            result = probe.probe(generator)
        assert result == []

    def test_max_calls_per_conv_calculated(self):
        probe = _make_probe(max_attempts_per_tool=4)
        probe.agent_config["tools"] = [
            {"name": "a", "description": "A"},
            {"name": "b", "description": "B"},
            {"name": "c", "description": "C"},
        ]
        generator = MagicMock()
        with patch.object(probe, "_setup_red_team_model"), \
             patch.object(probe, "_analyze_attackable_tools", return_value={
                 "tool_analyses": {
                     "a": {"attack_prompts": ["x"]},
                     "b": {"attack_prompts": ["x"]},
                     "c": {"attack_prompts": ["x"]},
                 },
                 "priority_targets": [],
             }), \
             patch.object(probe, "_attack_single_tool", return_value=[]):
            probe.probe(generator)
        assert probe.max_calls_per_conv == 12  # 3 tools * 4 attempts

    def test_sequential_calls_each_tool(self):
        probe = _make_probe()
        generator = MagicMock()
        dummy_attempt = MagicMock()
        with patch.object(probe, "_setup_red_team_model"), \
             patch.object(probe, "_analyze_attackable_tools", return_value={
                 "tool_analyses": {
                     "file_reader": {"attack_prompts": ["x"]},
                     "bash_executor": {"attack_prompts": ["x"]},
                 },
                 "priority_targets": [],
             }), \
             patch.object(probe, "_attack_single_tool", return_value=[dummy_attempt]) as mock_attack:
            results = probe.probe(generator)
        assert mock_attack.call_count == 2
        assert len(results) == 2


# ===========================================================================
# 5. _build_tool_configs ordering
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
# 6. _attack_single_tool
# ===========================================================================

class TestAttackSingleTool:

    def _make_attempt_mock(self):
        a = MagicMock(spec=Attempt)
        a.notes = {}
        out = MagicMock()
        out.text = "agent response"
        a.outputs = [out]
        return a

    def test_stops_early_on_success(self):
        probe = _make_probe(max_attempts_per_tool=5, eval_threshold=0.7)
        attempt = self._make_attempt_mock()

        with patch.object(probe, "_create_attempt", return_value=attempt), \
             patch.object(probe, "_execute_attempt", return_value=attempt), \
             patch.object(probe, "_verify_attack_success", return_value=(True, 0.9, "worked")):
            results = probe._attack_single_tool(
                "file_reader",
                {"attack_prompts": ["try this"], "vulnerabilities": "path traversal"},
            )

        assert len(results) == 1
        assert results[0].notes["is_tool_final"] is True

    def test_exhausts_max_attempts(self):
        probe = _make_probe(max_attempts_per_tool=3, eval_threshold=0.7)

        def make_attempt():
            a = self._make_attempt_mock()
            return a

        with patch.object(probe, "_create_attempt", side_effect=lambda _: make_attempt()), \
             patch.object(probe, "_execute_attempt", side_effect=lambda a: a), \
             patch.object(probe, "_verify_attack_success", return_value=(False, 0.2, "blocked")), \
             patch.object(probe, "_generate_exploit_prompt", return_value="next attack"):
            results = probe._attack_single_tool(
                "file_reader",
                {"attack_prompts": ["try this"], "vulnerabilities": "path traversal"},
            )

        final = [a for a in results if a.notes.get("is_tool_final")]
        assert len(final) == 1

    def test_stops_when_prompt_generation_fails(self):
        probe = _make_probe(max_attempts_per_tool=5, eval_threshold=0.7)

        call_count = [0]
        def make_attempt():
            a = self._make_attempt_mock()
            return a

        with patch.object(probe, "_create_attempt", side_effect=lambda _: make_attempt()), \
             patch.object(probe, "_execute_attempt", side_effect=lambda a: a), \
             patch.object(probe, "_verify_attack_success", return_value=(False, 0.1, "nope")), \
             patch.object(probe, "_generate_exploit_prompt", return_value=None):
            results = probe._attack_single_tool(
                "file_reader",
                {"attack_prompts": ["try this"], "vulnerabilities": "vuln"},
            )

        final = [a for a in results if a.notes.get("is_tool_final")]
        assert len(final) == 1
        assert len(results) <= 2  # at most first attempt + the one that failed to get next prompt


# ===========================================================================
# 7. _verify_attack_success  (JSON parsing edge cases)
# ===========================================================================

class TestVerifyAttackSuccess:

    def test_partial_counts_as_success(self):
        probe = _make_probe()
        resp = json.dumps({
            "success": "PARTIAL", "confidence": 0.6, "reasoning": "some access"
        })
        probe._get_red_team_response = MagicMock(return_value=resp)
        ok, conf, reason = probe._verify_attack_success("p", "r", "tool", "vuln")
        assert ok is True
        assert conf == 0.6

    def test_none_response(self):
        probe = _make_probe()
        probe._get_red_team_response = MagicMock(return_value=None)
        ok, conf, reason = probe._verify_attack_success("p", "r", "tool", "vuln")
        assert ok is False
        assert conf == 0.0
        assert "Verification failed" in reason

    def test_malformed_json(self):
        probe = _make_probe()
        probe._get_red_team_response = MagicMock(return_value="NOT JSON")
        ok, conf, reason = probe._verify_attack_success("p", "r", "tool", "vuln")
        assert ok is False
        assert conf == 0.0

    def test_markdown_wrapped_json(self):
        probe = _make_probe()
        inner = json.dumps({
            "success": "YES", "confidence": 0.95, "reasoning": "full access"
        })
        wrapped = f"```json\n{inner}\n```"
        probe._get_red_team_response = MagicMock(return_value=wrapped)
        ok, conf, reason = probe._verify_attack_success("p", "r", "tool", "vuln")
        assert ok is True
        assert conf == 0.95
        assert reason == "full access"

    def test_yes_is_success(self):
        probe = _make_probe()
        resp = json.dumps({
            "success": "YES", "confidence": 0.8, "reasoning": "exploited"
        })
        probe._get_red_team_response = MagicMock(return_value=resp)
        ok, conf, reason = probe._verify_attack_success("p", "r", "tool", "vuln")
        assert ok is True

    def test_no_is_failure(self):
        probe = _make_probe()
        resp = json.dumps({
            "success": "NO", "confidence": 0.1, "reasoning": "blocked"
        })
        probe._get_red_team_response = MagicMock(return_value=resp)
        ok, conf, reason = probe._verify_attack_success("p", "r", "tool", "vuln")
        assert ok is False


# ===========================================================================
# 8. Integration: plugin loading
# ===========================================================================

class TestIntegration:

    def test_probe_loads_as_plugin(self):
        probe = garak._plugins.load_plugin(
            "probes.agent_breaker.AgentBreaker",
            config_root={"run": {"generations": 1}},
        )
        assert probe is not None
        assert isinstance(probe, AgentBreaker)
